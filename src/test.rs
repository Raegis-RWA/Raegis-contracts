#![cfg(test)]

use super::*;
use crate::admin::{
    AdminTransferInitiatedEvent, AdminTransferredEvent, ContractPausedEvent, ContractUnpausedEvent,
    RoleAssignedEvent, RoleRevokedEvent,
};
use crate::asset::{AssetMintedEvent, TransferEvent, YieldDistributedEvent};
use crate::capabilities::{
    CapabilityStatus, ComplianceCapabilities, ContractCapabilities, EventCapabilities,
    MetadataCapabilities, MintingCapabilities, PauseCapabilities, SchemaVersionRelation,
    TransferCapabilities, CAPABILITY_SCHEMA_VERSION,
};

use crate::compliance::{
    ComplianceBatchUpdate, ComplianceStatus, ComplianceStatusChangedEvent, UserWhitelistedEvent,
    WhitelistRevokedEvent,
};

use crate::compliance_guards::TransitionGuard;

use crate::eligibility::InvestorEligibility;
use crate::issuer::{
    IssuanceGuard, IssuerDuty, IssuerSeparationPolicy, IssuerSeparationPolicyUpdatedEvent,
};
use crate::lifecycle::{AssetStatus, AssetStatusChangedEvent};

use crate::errors::Error;

use crate::restrictions::{code_for_reason, error_for_reason, reason_for_error, RestrictionReason};

use crate::ContractInitializedEvent;

use soroban_sdk::{
    testutils::{Address as _, Events as _},
    vec, Address, Env, IntoVal, String, Symbol,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn setup() -> (Env, AegisContractClient<'static>, Address, Address, Address) {
    let env = Env::default();
    let contract_id = env.register(AegisContract, ());
    let client = AegisContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);
    (env, client, admin, user1, user2)
}

#[allow(dead_code)]
fn setup_active() -> (Env, AegisContractClient<'static>, Address, Address, Address) {
    let env = Env::default();
    let contract_id = env.register(AegisContract, ());
    let client = AegisContractClient::new(&env, &contract_id);
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    (env, client, admin, user1, user2)
}

// ─── Happy-path lifecycle ─────────────────────────────────────────────────────

#[test]
fn test_lifecycle() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);

    client.set_role(&admin, &user1, &Role::ComplianceOfficer);
    client.set_role(&admin, &user2, &Role::AssetManager);

    client.whitelist_user(&user1, &user1);
    client.whitelist_user(&user1, &user2);

    client.mint_asset(&user2, &user1, &1000);
    client.transfer(&user1, &user2, &250);

    assert_eq!(client.get_role_of(&user1), Role::ComplianceOfficer);
    assert_eq!(client.get_role_of(&user2), Role::AssetManager);
}

// ─── Wrong-caller: mint_asset ────────────────────────────────────────────────

#[test]
fn test_mint_reverts_without_asset_manager_role() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.whitelist_user(&admin, &user2);

    // user1 has no role at all — mint should revert
    let result = client.try_mint_asset(&user1, &user2, &100);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    // Ensure state is preserved on wrong-role failure
    assert_eq!(client.get_total_supply(), 0);
    assert_eq!(client.get_balance_of(&user2), 0);
}

#[test]
fn test_mint_reverts_with_compliance_officer_role() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::ComplianceOfficer);
    client.whitelist_user(&admin, &user2);

    // ComplianceOfficer cannot mint — only AssetManager or Admin
    let result = client.try_mint_asset(&user1, &user2, &100);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    // Ensure state is preserved on wrong-role failure
    assert_eq!(client.get_total_supply(), 0);
    assert_eq!(client.get_balance_of(&user2), 0);
}

#[test]
fn test_mint_succeeds_with_asset_manager_role() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user2);

    let result = client.try_mint_asset(&user1, &user2, &100);
    assert!(result.is_ok());
}

#[test]
fn test_mint_reverts_with_invalid_amount() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user2);

    let result = client.try_mint_asset(&user1, &user2, &0);
    assert_eq!(result, Err(Ok(Error::InvalidAmount)));
}

#[test]
fn test_mint_reverts_when_receiver_not_whitelisted() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);

    // user2 was never whitelisted
    let result = client.try_mint_asset(&user1, &user2, &100);
    assert_eq!(result, Err(Ok(Error::ReceiverNotWhitelisted)));
}

#[test]
fn test_mint_succeeds_with_admin_role() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user2);

    // Admin can mint without an explicit AssetManager role assignment
    let result = client.try_mint_asset(&admin, &user2, &100);
    assert!(result.is_ok());
}

// ─── Transfer validation ──────────────────────────────────────────────────────

#[test]
fn test_transfer_reverts_with_invalid_amount() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);

    let result = client.try_transfer(&user1, &user2, &0);
    assert_eq!(result, Err(Ok(Error::InvalidAmount)));
}

#[test]
fn test_transfer_reverts_when_sender_not_whitelisted() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user2);

    // user1 was never whitelisted
    let result = client.try_transfer(&user1, &user2, &100);
    assert_eq!(result, Err(Ok(Error::SenderNotWhitelisted)));
}

#[test]
fn test_transfer_reverts_when_receiver_not_whitelisted() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user1);

    // user2 was never whitelisted
    let result = client.try_transfer(&user1, &user2, &100);
    assert_eq!(result, Err(Ok(Error::ReceiverNotWhitelisted)));
}

#[test]
fn test_transfer_reverts_with_insufficient_balance() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user1, &50);

    // user1 only has a balance of 50
    let result = client.try_transfer(&user1, &user2, &100);
    assert_eq!(result, Err(Ok(Error::InsufficientBalance)));
}

// ─── Wrong-caller: distribute_yield ───────────────────────────────────────────

#[test]
fn test_distribute_yield_reverts_without_role() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    let result = client.try_distribute_yield(&user1, &100);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));
}

#[test]
fn test_distribute_yield_reverts_with_compliance_officer_role() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::ComplianceOfficer);

    let result = client.try_distribute_yield(&user1, &100);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));
}

#[test]
fn test_distribute_yield_reverts_with_invalid_amount() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::AssetManager);

    let result = client.try_distribute_yield(&user1, &0);
    assert_eq!(result, Err(Ok(Error::InvalidAmount)));
}

#[test]
fn test_distribute_yield_succeeds_with_asset_manager_role() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::AssetManager);

    let result = client.try_distribute_yield(&user1, &100);
    assert!(result.is_ok());
}

// ─── Wrong-caller: whitelist_user ─────────────────────────────────────────────

#[test]
fn test_whitelist_reverts_without_role() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    // user2 has no role — whitelist should revert
    let result = client.try_whitelist_user(&user2, &user1);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    // Ensure state is preserved on wrong-role failure
    assert!(!client.is_whitelisted(&user1));
}

#[test]
fn test_whitelist_reverts_with_asset_manager_role() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user2, &Role::AssetManager);

    // AssetManager cannot whitelist — only ComplianceOfficer or Admin
    let result = client.try_whitelist_user(&user2, &user1);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    // Ensure state is preserved on wrong-role failure
    assert!(!client.is_whitelisted(&user1));
}

#[test]
fn test_whitelist_succeeds_with_compliance_officer_role() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user2, &Role::ComplianceOfficer);

    let result = client.try_whitelist_user(&user2, &user1);
    assert!(result.is_ok());
}

#[test]
fn test_whitelist_succeeds_with_admin_role() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    let result = client.try_whitelist_user(&admin, &user1);
    assert!(result.is_ok());
}

#[test]
fn test_whitelist_succeeds_with_emergency_officer_role() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user2, &Role::EmergencyOfficer);

    let result = client.try_whitelist_user(&user2, &user1);
    assert!(result.is_ok());
}

// ─── Wrong-caller: revoke_whitelist ───────────────────────────────────────────

#[test]
fn test_revoke_whitelist_reverts_without_role() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.whitelist_user(&admin, &user1);

    // user2 has no role
    let result = client.try_revoke_whitelist(&user2, &user1);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    // Ensure state is preserved on wrong-role failure
    assert!(client.is_whitelisted(&user1));
}

#[test]
fn test_revoke_whitelist_succeeds_with_compliance_officer_role() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user2, &Role::ComplianceOfficer);
    client.whitelist_user(&user2, &user1);

    let result = client.try_revoke_whitelist(&user2, &user1);
    assert!(result.is_ok());
}

// ─── Role management ─────────────────────────────────────────────────────────

#[test]
fn test_set_role_reverts_for_non_admin() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    // user1 is not admin — cannot assign roles
    let result = client.try_set_role(&user1, &user2, &Role::AssetManager);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    // Ensure state is preserved on wrong-role failure
    assert_eq!(client.get_role_of(&user2), Role::None);
}

#[test]
fn test_remove_role_reverts_for_non_admin() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::AssetManager);

    // user2 is not admin — cannot revoke roles
    let result = client.try_remove_role(&user2, &user1);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    // Ensure state is preserved on wrong-role failure
    assert_eq!(client.get_role_of(&user1), Role::AssetManager);
}

#[test]
fn test_remove_role_reverts_when_target_has_no_role() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    // user2 has no role — revoking should revert
    let result = client.try_remove_role(&admin, &user2);
    assert_eq!(result, Err(Ok(Error::NoRoleToRevoke)));
}

#[test]
fn test_cannot_assign_admin_role_via_set_role() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    // Trying to assign Admin role via set_role should revert
    let result = client.try_set_role(&admin, &user2, &Role::Admin);
    assert_eq!(result, Err(Ok(Error::CannotAssignAdminRole)));
}

#[test]
fn test_set_and_remove_role() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    client.set_role(&admin, &user2, &Role::AssetManager);
    assert_eq!(client.get_role_of(&user2), Role::AssetManager);

    client.remove_role(&admin, &user2);
    assert_eq!(client.get_role_of(&user2), Role::None);
}

#[test]
fn test_get_role_returns_none_for_unassigned() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    assert_eq!(client.get_role_of(&user2), Role::None);
}

// ─── Admin transfer (2-step) ─────────────────────────────────────────────────

#[test]
fn test_transfer_admin_reverts_for_non_admin() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    let result = client.try_transfer_admin(&user1, &user2);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    // Ensure state is preserved on wrong-role failure
    assert_eq!(client.get_role_of(&admin), Role::Admin);
}

#[test]
fn test_accept_admin_reverts_for_wrong_candidate() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.transfer_admin(&admin, &user1);

    // user2 tries to accept — should revert
    let result = client.try_accept_admin(&user2);
    assert_eq!(result, Err(Ok(Error::NotPendingCandidate)));

    // Ensure state is preserved on wrong-role failure
    assert_eq!(client.get_role_of(&admin), Role::Admin);
    assert_eq!(client.get_role_of(&user1), Role::None);
    assert_eq!(client.get_role_of(&user2), Role::None);
}

#[test]
fn test_accept_admin_reverts_without_pending_transfer() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    // No transfer initiated — accept should revert
    let result = client.try_accept_admin(&user2);
    assert_eq!(result, Err(Ok(Error::NoPendingAdminTransfer)));
}

#[test]
fn test_full_admin_transfer() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    // Step 1: Current admin initiates transfer
    client.transfer_admin(&admin, &user1);

    // Step 2: Candidate accepts
    client.accept_admin(&user1);

    // Verify: user1 is now admin, admin is no longer admin
    assert_eq!(client.get_role_of(&user1), Role::Admin);
    assert_eq!(client.get_role_of(&admin), Role::None);
}

// ─── Renounce admin ──────────────────────────────────────────────────────────

#[test]
fn test_renounce_admin_reverts_for_non_admin() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    let result = client.try_renounce_admin(&user1);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    // Ensure state is preserved on wrong-role failure
    assert_eq!(client.get_role_of(&admin), Role::Admin);
}

#[test]
fn test_renounce_admin_removes_admin() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    assert_eq!(client.get_role_of(&admin), Role::Admin);

    client.renounce_admin(&admin);
    assert_eq!(client.get_role_of(&admin), Role::None);
}

// ─── Double initialization ───────────────────────────────────────────────────

#[test]
fn test_double_initialization_reverts() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    let result = client.try_initialize(&user1);
    assert_eq!(result, Err(Ok(Error::AlreadyInitialized)));
}

// ─── Storage: uninitialized contract ──────────────────────────────────────────

#[test]
fn test_set_role_reverts_when_not_initialized() {
    let (env, client, _admin, user1, user2) = setup();
    env.mock_all_auths();

    // No `initialize` call — the Admin key is missing from storage entirely.
    let result = client.try_set_role(&user1, &user2, &Role::AssetManager);
    assert_eq!(result, Err(Ok(Error::NotInitialized)));
}

// ─── Pause: authorization ─────────────────────────────────────────────────────

#[test]
fn test_pause_reverts_for_unauthorized() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    // user1 has no role — cannot pause
    let result = client.try_pause(&user1);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));
}

#[test]
fn test_pause_succeeds_for_admin() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    let result = client.try_pause(&admin);
    assert!(result.is_ok());
    assert!(client.is_paused());
}

#[test]
fn test_pause_succeeds_for_emergency_officer() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::EmergencyOfficer);

    let result = client.try_pause(&user1);
    assert!(result.is_ok());
    assert!(client.is_paused());
}

#[test]
fn test_pause_reverts_when_already_paused() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.pause(&admin);

    // Second pause should revert
    let result = client.try_pause(&admin);
    assert_eq!(result, Err(Ok(Error::AlreadyPaused)));
}

#[test]
fn test_unpause_reverts_for_non_admin() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.pause(&admin);

    // user1 is not admin — cannot unpause
    let result = client.try_unpause(&user1);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));
}

#[test]
fn test_unpause_reverts_for_emergency_officer() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::EmergencyOfficer);
    client.pause(&admin);

    // EmergencyOfficer can pause but cannot unpause
    let result = client.try_unpause(&user1);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));
}

#[test]
fn test_unpause_succeeds_for_admin() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.pause(&admin);
    assert!(client.is_paused());

    let result = client.try_unpause(&admin);
    assert!(result.is_ok());
    assert!(!client.is_paused());
}

#[test]
fn test_unpause_reverts_when_not_paused() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    // Contract is not paused — unpause should revert
    let result = client.try_unpause(&admin);
    assert_eq!(result, Err(Ok(Error::NotPaused)));
}

// ─── Pause: blocked state-changing operations ─────────────────────────────────

#[test]
fn test_mint_blocked_when_paused() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user2);

    // Mint should succeed before pause
    let result = client.try_mint_asset(&user1, &user2, &100);
    assert!(result.is_ok());

    client.pause(&admin);

    // Mint should fail when paused
    let result = client.try_mint_asset(&user1, &user2, &100);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
}

#[test]
fn test_transfer_blocked_when_paused() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::ComplianceOfficer);
    client.set_role(&admin, &user2, &Role::AssetManager);
    client.whitelist_user(&user1, &user1);
    client.whitelist_user(&user1, &user2);
    client.mint_asset(&user2, &user1, &1000);

    // Transfer should succeed before pause
    let result = client.try_transfer(&user1, &user2, &250);
    assert!(result.is_ok());

    client.pause(&admin);

    // Transfer should fail when paused
    let result = client.try_transfer(&user1, &user2, &250);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
}

#[test]
fn test_whitelist_blocked_when_paused() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::ComplianceOfficer);

    client.pause(&admin);

    // Whitelist should fail when paused
    let result = client.try_whitelist_user(&user1, &user2);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
}

#[test]
fn test_revoke_whitelist_blocked_when_paused() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::ComplianceOfficer);
    client.whitelist_user(&user1, &user2);

    client.pause(&admin);

    // Revoke whitelist should fail when paused
    let result = client.try_revoke_whitelist(&user1, &user2);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
}

#[test]
fn test_distribute_yield_blocked_when_paused() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::AssetManager);

    client.pause(&admin);

    // Distribute yield should fail when paused
    let result = client.try_distribute_yield(&user1, &100);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
}

#[test]
fn test_set_role_blocked_when_paused() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    client.pause(&admin);

    // set_role is an admin operation — also blocked during pause
    let result = client.try_set_role(&admin, &user1, &Role::AssetManager);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
}

#[test]
fn test_remove_role_blocked_when_paused() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user2, &Role::AssetManager);

    client.pause(&admin);

    // remove_role is also blocked during pause
    let result = client.try_remove_role(&admin, &user2);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
}

// ─── Pause: read functions remain available ───────────────────────────────────

#[test]
fn test_read_functions_available_when_paused() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::ComplianceOfficer);
    client.set_role(&admin, &user2, &Role::AssetManager);
    client.whitelist_user(&user1, &user1);
    client.whitelist_user(&user1, &user2);
    client.mint_asset(&user2, &user1, &1000);

    client.pause(&admin);

    // Read functions should all still work
    assert!(client.is_paused());
    assert_eq!(client.get_role_of(&user1), Role::ComplianceOfficer);
    assert_eq!(client.get_role_of(&user2), Role::AssetManager);
    assert_eq!(client.get_balance_of(&user1), 1000);
    assert_eq!(client.get_balance_of(&user2), 0);
    assert!(client.is_whitelisted(&user1));
    assert!(client.is_whitelisted(&user2));
    assert_eq!(client.get_total_supply(), 1000);
}

// ─── Pause: full lifecycle ────────────────────────────────────────────────────

#[test]
fn test_pause_unpause_full_lifecycle() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::ComplianceOfficer);
    client.set_role(&admin, &user2, &Role::AssetManager);
    client.whitelist_user(&user1, &user1);
    client.whitelist_user(&user1, &user2);

    // Operations work before pause
    client.mint_asset(&user2, &user1, &1000);
    client.transfer(&user1, &user2, &250);
    assert_eq!(client.get_balance_of(&user1), 750);
    assert_eq!(client.get_balance_of(&user2), 250);

    // Pause blocks operations
    client.pause(&admin);
    assert!(client.is_paused());

    let result = client.try_mint_asset(&user2, &user1, &500);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
    let result = client.try_transfer(&user1, &user2, &100);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
    let result = client.try_whitelist_user(&user1, &Address::generate(&env));
    assert_eq!(result, Err(Ok(Error::ContractPaused)));

    // Unpause restores operations
    client.unpause(&admin);
    assert!(!client.is_paused());

    client.mint_asset(&user2, &user1, &500);
    client.transfer(&user1, &user2, &100);
    assert_eq!(client.get_balance_of(&user1), 1150);
    assert_eq!(client.get_balance_of(&user2), 350);
}

// ─── Event compatibility: compliance & minting ────────────────────────────────
//
// These tests lock down the exact topic and payload shape of each event so
// that downstream SDKs, dashboards, and indexers relying on this contract's
// event schema get a compile-time-checked regression signal if the shape
// ever drifts. `env.events().all()` returns only the events published by the
// most recent top-level invocation, so each test calls the action under
// test as the last client call before asserting.

#[test]
fn test_whitelist_user_emits_event() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.whitelist_user(&admin, &user1);

    // The lifecycle transition event is emitted first, then the legacy
    // `user_whitelisted` event is retained for backwards compatibility.
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("compliance_status_changed",).into_val(&env),
                ComplianceStatusChangedEvent {
                    caller: admin.clone(),
                    user: user1.clone(),
                    previous_status: crate::compliance::ComplianceStatus::Unknown,
                    new_status: crate::compliance::ComplianceStatus::Approved,
                }
                .into_val(&env),
            ),
            (
                client.address.clone(),
                ("user_whitelisted",).into_val(&env),
                UserWhitelistedEvent {
                    caller: admin,
                    user: user1,
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_revoke_whitelist_emits_event() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.whitelist_user(&admin, &user1);
    client.revoke_whitelist(&admin, &user1);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("compliance_status_changed",).into_val(&env),
                ComplianceStatusChangedEvent {
                    caller: admin.clone(),
                    user: user1.clone(),
                    previous_status: crate::compliance::ComplianceStatus::Approved,
                    new_status: crate::compliance::ComplianceStatus::Revoked,
                }
                .into_val(&env),
            ),
            (
                client.address.clone(),
                ("whitelist_revoked",).into_val(&env),
                WhitelistRevokedEvent {
                    caller: admin,
                    user: user1,
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_mint_asset_emits_event_with_running_supply() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user2);

    // First mint establishes a baseline supply.
    client.mint_asset(&user1, &user2, &400);

    // Second mint's event should reflect the *cumulative* total supply, not
    // just the minted amount.
    client.mint_asset(&user1, &user2, &600);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("asset_minted",).into_val(&env),
                AssetMintedEvent {
                    caller: user1,
                    to: user2,
                    amount: 600,
                    total_supply: 1000,
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_transfer_emits_event() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user1, &1000);

    client.transfer(&user1, &user2, &250);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("transfer",).into_val(&env),
                TransferEvent {
                    from: user1,
                    to: user2,
                    amount: 250,
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_blocked_transfer_emits_no_event() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user1);
    // user2 is deliberately left off the whitelist.

    // Reverted invocations discard their events entirely — the standardized
    // `ReceiverNotWhitelisted` error code is the only observable signal for
    // a compliance-restricted transfer (see docs/events.md).
    let result = client.try_transfer(&user1, &user2, &100);
    assert_eq!(result, Err(Ok(Error::ReceiverNotWhitelisted)));
    assert_eq!(env.events().all().events().len(), 0);
}

#[test]
fn test_distribute_yield_emits_event() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::AssetManager);

    client.distribute_yield(&user1, &500);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("yield_distributed",).into_val(&env),
                YieldDistributedEvent {
                    caller: user1,
                    amount: 500,
                }
                .into_val(&env),
            ),
        ]
    );
}

// ─── Event compatibility: admin, role & governance ────────────────────────────
//
// These tests lock down the exact topic and payload shape of every
// role-related and admin-related event so downstream audit-trail UIs,
// dashboards, and indexers get a compile-time-checked regression signal if
// the schema ever drifts.

#[test]
fn test_initialize_emits_event() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("contract_initialized",).into_val(&env),
                ContractInitializedEvent { admin }.into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_set_role_emits_event() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::ComplianceOfficer);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("role_assigned",).into_val(&env),
                RoleAssignedEvent {
                    admin: admin.clone(),
                    target: user1,
                    role: Role::ComplianceOfficer,
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_remove_role_emits_event() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.remove_role(&admin, &user1);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("role_revoked",).into_val(&env),
                RoleRevokedEvent {
                    admin: admin.clone(),
                    target: user1,
                    role: Role::AssetManager,
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_transfer_admin_emits_event() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.transfer_admin(&admin, &user2);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("admin_transfer_initiated",).into_val(&env),
                AdminTransferInitiatedEvent {
                    current_admin: admin,
                    candidate: user2,
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_accept_admin_emits_event() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.transfer_admin(&admin, &user2);
    client.accept_admin(&user2);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("admin_transferred",).into_val(&env),
                AdminTransferredEvent {
                    previous_admin: admin,
                    new_admin: user2,
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_renounce_admin_emits_event() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.renounce_admin(&admin);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("admin_renounced",).into_val(&env),
                AdminTransferredEvent {
                    previous_admin: admin.clone(),
                    new_admin: admin,
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_pause_emits_event() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.pause(&admin);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("contract_paused",).into_val(&env),
                ContractPausedEvent { admin }.into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_unpause_emits_event() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.pause(&admin);
    client.unpause(&admin);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("contract_unpaused",).into_val(&env),
                ContractUnpausedEvent { admin }.into_val(&env),
            ),
        ]
    );
}

// ─── Supply cap amendment governance (#32) ────────────────────────────────────

#[test]
fn test_supply_cap_default_is_unbounded() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user2);

    // No cap set yet → minting is not blocked by a cap.
    assert_eq!(client.get_supply_cap(), 0);
    assert!(client.get_pending_supply_cap().is_none());
    let r = client.try_mint_asset(&admin, &user2, &1000);
    assert!(r.is_ok());
}

#[test]
fn test_supply_cap_requires_two_step_governance() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user2);

    // Non-admin cannot propose.
    let r = client.try_propose_supply_cap(&user1, &1000);
    assert!(r.is_err());

    // Propose, then cap is still not active (no-op until accepted).
    client.propose_supply_cap(&admin, &1000);
    assert_eq!(client.get_supply_cap(), 0);
    assert_eq!(client.get_pending_supply_cap(), Some(1000));

    // Mint below proposed cap still works (active cap is still 0).
    let r = client.try_mint_asset(&admin, &user2, &500);
    assert!(r.is_ok());

    // Accept activates the cap.
    client.accept_supply_cap(&admin);
    assert_eq!(client.get_supply_cap(), 1000);
    assert!(client.get_pending_supply_cap().is_none());

    // Now minting above the cap is rejected.
    let r = client.try_mint_asset(&admin, &user2, &600);
    assert!(r.is_err());

    // Minting up to the cap is allowed.
    let r = client.try_mint_asset(&admin, &user2, &500);
    assert!(r.is_ok());
}

#[test]
fn test_supply_cap_proposal_cancel() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    client.propose_supply_cap(&admin, &500);
    assert_eq!(client.get_pending_supply_cap(), Some(500));

    // Cancel clears the proposal; accept should then fail.
    client.cancel_supply_cap_proposal(&admin);
    assert!(client.get_pending_supply_cap().is_none());

    let r = client.try_accept_supply_cap(&admin);
    assert!(r.is_err());
    assert_eq!(client.get_supply_cap(), 0);
}

#[test]
fn test_supply_cap_noop_rejected() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    // Proposing the same value as the active cap (0) is a no-op → rejected.
    let r = client.try_propose_supply_cap(&admin, &0);
    assert!(r.is_err());
}

// ─── INVALID INPUT MATRIX TESTS (Audit Readiness) ─────────────────────────────
// Deterministic matrix covering malformed, boundary, zero, oversized, unauthorised,
// invalid-state inputs across compliance, role, asset, minting, transfer, and config.
// Every failure MUST leave contract state unchanged.

#[test]
fn test_supply_cap_negative_rejected() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    // ── Pre-state snapshot (baseline) ───────────────────────────────────────

    // ── 1. CONFIG / INITIALIZATION ──────────────────────────────────────────
    let r = client.try_propose_supply_cap(&admin, &-1);
    assert!(r.is_err());
}

#[test]
fn test_supply_cap_lowering_below_supply_blocks_future_mints() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user2);

    client.mint_asset(&admin, &user2, &1000);
    assert_eq!(client.get_total_supply(), 1000);

    // Lower the cap below current supply (allowed — does not burn supply).
    client.propose_supply_cap(&admin, &500);
    client.accept_supply_cap(&admin);
    assert_eq!(client.get_supply_cap(), 500);

    // Existing supply (1000) now exceeds the cap; further mints are blocked
    // until supply falls or the cap is raised.
    let r = client.try_mint_asset(&admin, &user2, &1);
    assert!(r.is_err());
}

#[test]
fn test_supply_cap_zero_mint_rejected_without_state_change() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user2);
    client.propose_supply_cap(&admin, &1000);
    client.accept_supply_cap(&admin);

    assert_eq!(client.get_total_supply(), 0);
    assert_eq!(client.get_balance_of(&user2), 0);

    let r = client.try_mint_asset(&admin, &user2, &0);
    assert_eq!(r, Err(Ok(Error::InvalidAmount)));

    // Failed mint must not mutate supply or recipient balance.
    assert_eq!(client.get_total_supply(), 0);
    assert_eq!(client.get_balance_of(&user2), 0);
}

#[test]
fn test_supply_cap_boundary_and_exceeded_preserve_state() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user2);
    client.propose_supply_cap(&admin, &1000);
    client.accept_supply_cap(&admin);

    // Exactly at cap must succeed.
    let r = client.try_mint_asset(&admin, &user2, &1000);
    assert!(r.is_ok());
    assert_eq!(client.get_total_supply(), 1000);
    assert_eq!(client.get_balance_of(&user2), 1000);

    // Any additional mint must fail and keep state unchanged.
    let r = client.try_mint_asset(&admin, &user2, &1);
    assert!(r.is_err());
    assert_eq!(client.get_total_supply(), 1000);
    assert_eq!(client.get_balance_of(&user2), 1000);
}

#[test]
fn test_supply_cap_repeated_minting_near_cap_then_rejects() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user2);
    client.propose_supply_cap(&admin, &1000);
    client.accept_supply_cap(&admin);

    // Repeated mints approaching the cap.
    let matrix = [300_i128, 300_i128, 399_i128, 1_i128];
    for amount in matrix {
        let r = client.try_mint_asset(&admin, &user2, &amount);
        assert!(r.is_ok());
    }
    assert_eq!(client.get_total_supply(), 1000);
    assert_eq!(client.get_balance_of(&user2), 1000);

    // Any extra amount must fail with no state drift.
    let r = client.try_mint_asset(&admin, &user2, &1);
    assert!(r.is_err());
    assert_eq!(client.get_total_supply(), 1000);
    assert_eq!(client.get_balance_of(&user2), 1000);
}

#[test]
fn test_supply_cap_overflow_like_mint_keeps_state_consistent() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user2);
    client.propose_supply_cap(&admin, &i128::MAX);
    client.accept_supply_cap(&admin);

    // Reach the practical numeric boundary first.
    let r = client.try_mint_asset(&admin, &user2, &i128::MAX);
    assert!(r.is_ok());
    assert_eq!(client.get_balance_of(&user2), i128::MAX);

    // While the contract is globally paused, the pause outranks the asset
    // lifecycle state — the reported reason must match that precedence.

    // Unpause when not paused (after unpause)

    // Once unpaused, the retired asset yields its own specific reason code
    // rather than the generic `AssetNotActive` this matrix used to see.

    // Unpause when not paused (after unpause)

    // A retired asset blocks every transfer regardless of compliance state.
    let r = client.try_mint_asset(&admin, &user2, &1);
    assert!(r.is_err());
    assert_eq!(client.get_total_supply(), i128::MAX);
    assert_eq!(client.get_balance_of(&user2), i128::MAX);

    // ── FINAL STATE VERIFICATION: NO MUTATION ───────────────────────────────
}

// ─── Contract capability flags (#82) ─────────────────────────────────────────
//
// These tests lock down the read-only capability surface that SDK and
// dashboard clients feature-gate against. They assert three things: the
// default capability state on a fresh deployment, that the helper never
// mutates state, and that unsupported/planned states are distinguishable.

/// The full expected capability descriptor for a freshly deployed contract
/// with no admin, no caps, no metadata, and no pause. Built as a helper so
/// each test can assert against an exhaustive struct literal — adding a
/// field to any capability struct fails compilation here until the expected
/// default is declared, which is the point.
fn default_capabilities(env: &Env) -> ContractCapabilities {
    ContractCapabilities {
        capability_version: CAPABILITY_SCHEMA_VERSION,
        contract_version: String::from_str(env, env!("CARGO_PKG_VERSION")),
        initialized: false,
        rbac: CapabilityStatus::Supported,
        two_step_governance: CapabilityStatus::Supported,
        sep41_token_interface: CapabilityStatus::Planned,
        compliance: ComplianceCapabilities {
            module_enabled: true,
            whitelist: CapabilityStatus::Supported,
            whitelist_revocation: CapabilityStatus::Supported,
            batch_whitelisting: CapabilityStatus::Supported,
            batch_status_updates: CapabilityStatus::Supported,
            investor_tiers: CapabilityStatus::Unsupported,
            lifecycle_states: CapabilityStatus::Supported,
            lifecycle_transitions: CapabilityStatus::Supported,
            transition_guards: CapabilityStatus::Supported,
            eligibility_reads: CapabilityStatus::Supported,
            enforced_on_mint: true,
            enforced_on_transfer: true,
        },
        minting: MintingCapabilities {
            module_enabled: true,
            minting: CapabilityStatus::Supported,
            burning: CapabilityStatus::Unsupported,
            supply_cap: CapabilityStatus::Supported,
            supply_cap_enforced: false,
            yield_distribution: CapabilityStatus::Planned,
            issuer_separation: CapabilityStatus::Supported,
            issuer_separation_enforced: false,
        },
        transfers: TransferCapabilities {
            module_enabled: true,
            transfers: CapabilityStatus::Supported,
            holding_cap: CapabilityStatus::Supported,
            holding_cap_enforced: false,
            allowances: CapabilityStatus::Planned,
            transfer_from: CapabilityStatus::Planned,
            transfer_fees: CapabilityStatus::Planned,
            transfer_eligibility_check: CapabilityStatus::Supported,
            transfer_restriction_reasons: CapabilityStatus::Supported,
        },
        pause: PauseCapabilities {
            module_enabled: true,
            global_pause: CapabilityStatus::Supported,
            paused: false,
            asset_lifecycle: CapabilityStatus::Supported,
            asset_active: true,
            operations_enabled: true,
        },
        metadata: MetadataCapabilities {
            module_enabled: true,
            name_and_symbol: CapabilityStatus::Supported,
            metadata_uri: CapabilityStatus::Supported,
            decimals: CapabilityStatus::Planned,
            metadata_configured: false,
            lifecycle_restricted: true,
        },
        events: EventCapabilities {
            module_enabled: true,
            compliance_events: CapabilityStatus::Supported,
            compliance_lifecycle_events: CapabilityStatus::Supported,
            minting_events: CapabilityStatus::Supported,
            transfer_events: CapabilityStatus::Supported,
            admin_events: CapabilityStatus::Supported,
            governance_events: CapabilityStatus::Supported,
            asset_lifecycle_events: CapabilityStatus::Supported,
            transfer_restriction_events: CapabilityStatus::Unsupported,
            asset_registered_event: CapabilityStatus::Planned,
        },
        config: crate::capabilities::ConfigCapabilities {
            module_enabled: true,
            global_config: CapabilityStatus::Supported,
        },
    }
}

#[test]
fn test_contract_capabilities() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    // 1. Before initialization (asset starts in Draft state)
    let caps_before = client.get_capabilities();
    let mut expected = default_capabilities(&env);
    expected.pause.asset_active = false;
    expected.pause.operations_enabled = false;
    assert_eq!(caps_before, expected);

    // supports_capability works before initialization
    assert_eq!(
        client.supports_capability(&Symbol::new(&env, "whitelist")),
        CapabilityStatus::Supported
    );

    // 2. After initialization (still in Draft state)
    client.initialize(&admin);
    let caps_after_init = client.get_capabilities();
    expected.initialized = true;
    assert_eq!(caps_after_init, expected);

    // 3. After setting status to Active
    client.set_asset_status(&admin, &AssetStatus::Active);
    let caps_after_active = client.get_capabilities();
    expected.pause.asset_active = true;
    expected.pause.operations_enabled = true;
    assert_eq!(caps_after_active, expected);

    // 3. Read-only / no state changes
    // Calling capability endpoints must publish no events and not modify balances or storage
    let events_len = env.events().all().events().len();
    let _ = client.get_capabilities();
    let _ = client.supports_capability(&Symbol::new(&env, "whitelist"));
    let _ = client.get_capability_keys();
    assert_eq!(env.events().all().events().len(), events_len);

    // 4. Backward compatibility: unknown capability returns Unsupported
    assert_eq!(
        client.supports_capability(&Symbol::new(&env, "some_future_capability")),
        CapabilityStatus::Unsupported
    );

    // 5. Check capability keys registry agreement
    let keys = client.get_capability_keys();
    assert_eq!(keys.len(), 34);
    assert!(keys.contains(Symbol::new(&env, "whitelist")));
    assert!(keys.contains(Symbol::new(&env, "rbac")));
}

// ─── Asset lifecycle invariants (#55) ─────────────────────────────────────────

#[test]
fn test_asset_lifecycle_defaults_to_draft() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    assert_eq!(client.get_asset_status(), AssetStatus::Draft);
}

#[test]
fn test_asset_lifecycle_wrong_caller_transition_rejected() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    // user1 has no emergency/admin privileges for lifecycle transitions.
    let r = client.try_set_asset_status(&user1, &AssetStatus::Paused);
    assert_eq!(r, Err(Ok(Error::Unauthorized)));
    assert_eq!(client.get_asset_status(), AssetStatus::Draft);
}

#[test]
fn test_asset_lifecycle_invalid_transition_rejected_with_state_consistency() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_asset_status(&admin, &AssetStatus::Retired);
    assert_eq!(client.get_asset_status(), AssetStatus::Retired);

    // Retired is terminal in the lifecycle model.
    let r = client.try_set_asset_status(&admin, &AssetStatus::Active);
    assert_eq!(r, Err(Ok(Error::InvalidLifecycleTransition)));
    assert_eq!(client.get_asset_status(), AssetStatus::Retired);
}

#[test]
fn test_asset_paused_blocks_mint_and_transfer_with_unchanged_state() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user1, &500);

    client.set_asset_status(&admin, &AssetStatus::Paused);

    let supply_before = client.get_total_supply();
    let user1_before = client.get_balance_of(&user1);
    let user2_before = client.get_balance_of(&user2);

    let mint_r = client.try_mint_asset(&user1, &user2, &10);
    assert_eq!(mint_r, Err(Ok(Error::AssetPausedRestriction)));

    let transfer_r = client.try_transfer(&user1, &user2, &10);
    assert_eq!(transfer_r, Err(Ok(Error::AssetPausedRestriction)));

    // Failed operations must not mutate balances/supply.
    assert_eq!(client.get_total_supply(), supply_before);
    assert_eq!(client.get_balance_of(&user1), user1_before);
    assert_eq!(client.get_balance_of(&user2), user2_before);
}

#[test]
fn test_asset_retired_blocks_mint_transfer_and_metadata_update() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user1, &200);
    client.set_asset_status(&admin, &AssetStatus::Retired);
    let supply_before = client.get_total_supply();
    let user1_before = client.get_balance_of(&user1);
    let user2_before = client.get_balance_of(&user2);
    let metadata_before = client.get_asset_metadata();

    let mint_r = client.try_mint_asset(&user1, &user2, &1);
    assert_eq!(mint_r, Err(Ok(Error::AssetRetiredRestriction)));

    let transfer_r = client.try_transfer(&user1, &user2, &1);
    assert_eq!(transfer_r, Err(Ok(Error::AssetRetiredRestriction)));

    let metadata_r = client.try_update_asset_metadata(
        &user1,
        &String::from_str(&env, "Retired Name"),
        &String::from_str(&env, "RET"),
        &String::from_str(&env, "ipfs://retired"),
    );
    assert_eq!(metadata_r, Err(Ok(Error::AssetMetadataUpdateBlocked)));

    // Failed operations keep all tracked state unchanged.
    assert_eq!(client.get_total_supply(), supply_before);
    assert_eq!(client.get_balance_of(&user1), user1_before);
    assert_eq!(client.get_balance_of(&user2), user2_before);
    assert_eq!(client.get_asset_metadata(), metadata_before);
}

#[test]
fn test_asset_blocked_blocks_mint_and_transfer() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user1, &100);

    client.set_asset_status(&admin, &AssetStatus::Blocked);
    let supply_before = client.get_total_supply();
    let user1_before = client.get_balance_of(&user1);
    let user2_before = client.get_balance_of(&user2);
    let metadata_before = client.get_asset_metadata();

    let mint_r = client.try_mint_asset(&user1, &user2, &10);
    assert_eq!(mint_r, Err(Ok(Error::AssetBlockedRestriction)));

    let transfer_r = client.try_transfer(&user1, &user2, &10);
    assert_eq!(transfer_r, Err(Ok(Error::AssetBlockedRestriction)));

    let metadata_r = client.try_update_asset_metadata(
        &user1,
        &String::from_str(&env, "Blocked Name"),
        &String::from_str(&env, "BLK"),
        &String::from_str(&env, "ipfs://blocked"),
    );
    assert_eq!(metadata_r, Err(Ok(Error::AssetMetadataUpdateBlocked)));

    assert_eq!(client.get_total_supply(), supply_before);
    assert_eq!(client.get_balance_of(&user1), user1_before);
    assert_eq!(client.get_balance_of(&user2), user2_before);
    assert_eq!(client.get_asset_metadata(), metadata_before);
}

#[test]
fn test_asset_metadata_update_allowed_in_active_and_paused() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);

    let r = client.try_update_asset_metadata(
        &user1,
        &String::from_str(&env, "Aegis Real Estate Trust"),
        &String::from_str(&env, "AERT"),
        &String::from_str(&env, "ipfs://aegis/asset/1"),
    );
    assert!(r.is_ok());

    client.set_asset_status(&admin, &AssetStatus::Paused);
    let r = client.try_update_asset_metadata(
        &user1,
        &String::from_str(&env, "Aegis Real Estate Trust v2"),
        &String::from_str(&env, "AERT"),
        &String::from_str(&env, "ipfs://aegis/asset/2"),
    );
    assert!(r.is_ok());
}

#[test]
fn test_asset_admin_transfer_still_works_when_asset_paused() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_asset_status(&admin, &AssetStatus::Paused);

    // Asset lifecycle pause restricts mint/transfer, but governance can still
    // rotate admin keys for operational recovery.
    let r = client.try_transfer_admin(&admin, &user1);
    assert!(r.is_ok());
    let r = client.try_accept_admin(&user1);
    assert!(r.is_ok());
    assert_eq!(client.get_role_of(&user1), Role::Admin);
}

#[test]
fn test_asset_admin_transfer_still_works_when_asset_blocked_or_retired() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_asset_status(&admin, &AssetStatus::Blocked);

    // Governance/admin changes are still allowed in blocked status.
    let r = client.try_transfer_admin(&admin, &user1);
    assert!(r.is_ok());
    let r = client.try_accept_admin(&user1);
    assert!(r.is_ok());
    assert_eq!(client.get_role_of(&user1), Role::Admin);

    client.set_asset_status(&user1, &AssetStatus::Active);
    client.set_asset_status(&user1, &AssetStatus::Retired);
    assert_eq!(client.get_asset_status(), AssetStatus::Retired);

    // Governance/admin changes are still allowed in retired status.
    let r = client.try_transfer_admin(&user1, &user2);
    assert!(r.is_ok());
    let r = client.try_accept_admin(&user2);
    assert!(r.is_ok());
    assert_eq!(client.get_role_of(&user2), Role::Admin);
}

// ─── Investor holding restriction checks (#33) ───────────────────────────────

#[test]
fn test_holding_cap_default_is_unrestricted() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user2);

    // No holding cap set → minting to a holder is not blocked by a cap.
    assert_eq!(client.get_holding_cap(), 0);
    let r = client.try_mint_asset(&user1, &user2, &10000);
    assert!(r.is_ok());
    assert_eq!(client.get_balance_of(&user2), 10000);
}

#[test]
fn test_holding_cap_blocks_mint_over_limit() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user2);

    // Propose + accept a holding cap of 500.
    client.propose_holding_cap(&admin, &500);
    client.accept_holding_cap(&admin);
    assert_eq!(client.get_holding_cap(), 500);

    // Mint up to the cap is allowed.
    let r = client.try_mint_asset(&user1, &user2, &500);
    assert!(r.is_ok());
    assert_eq!(client.get_balance_of(&user2), 500);

    // Mint that would push the holder over the cap is rejected.
    let r = client.try_mint_asset(&user1, &user2, &1);
    assert!(r.is_err());
}

#[test]
fn test_holding_cap_blocks_transfer_over_limit() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);

    // Give user1 a balance, then cap user2's holding at 300.
    client.mint_asset(&user1, &user1, &1000);
    client.propose_holding_cap(&admin, &300);
    client.accept_holding_cap(&admin);

    // Transfer that would push user2 over 300 is rejected.
    let r = client.try_transfer(&user1, &user2, &301);
    assert!(r.is_err());

    // Transfer within the cap is allowed.
    let r = client.try_transfer(&user1, &user2, &300);
    assert!(r.is_ok());
    assert_eq!(client.get_balance_of(&user2), 300);
}

#[test]
fn test_holding_cap_governance_requires_admin_and_two_steps() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    // Non-admin cannot propose.
    let r = client.try_propose_holding_cap(&user1, &100);
    assert!(r.is_err());

    // Propose, then cap is still not active.
    client.propose_holding_cap(&admin, &100);
    assert_eq!(client.get_holding_cap(), 0);
    assert_eq!(client.get_pending_holding_cap(), Some(100));

    // Accept activates it.
    client.accept_holding_cap(&admin);
    assert_eq!(client.get_holding_cap(), 100);
    assert!(client.get_pending_holding_cap().is_none());

    // No-op proposal (== active) is rejected.
    let r = client.try_propose_holding_cap(&admin, &100);
    assert!(r.is_err());

    // Negative proposal is rejected.
    let r = client.try_propose_holding_cap(&admin, &-1);
    assert!(r.is_err());
}

// ─── Investor eligibility read helpers (#14) ─────────────────────────────────

#[test]
fn test_eligibility_default_state_is_ineligible() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);

    // user2 was never whitelisted and has never held a balance.
    let elig = client.get_investor_eligibility(&user2);
    assert_eq!(
        elig,
        InvestorEligibility {
            whitelisted: false,
            compliance_status: ComplianceStatus::Unknown,
            contract_paused: false,
            asset_status: AssetStatus::Draft,
            balance: 0,
            holding_cap: 0,
            remaining_capacity: None,
            can_receive: false,
            can_send: false,
        }
    );
}

#[test]
fn test_eligibility_reflects_whitelisted_holder_with_balance() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user2, &500);

    let elig = client.get_investor_eligibility(&user2);
    assert_eq!(
        elig,
        InvestorEligibility {
            whitelisted: true,
            compliance_status: ComplianceStatus::Approved,
            contract_paused: false,
            asset_status: AssetStatus::Active,
            balance: 500,
            holding_cap: 0,
            remaining_capacity: None,
            can_receive: true,
            can_send: true,
        }
    );
}

// ─── Transfer restriction reason codes ───────────────────────────────────────
//
// These tests lock down the blocked-transfer reason surface that SDK and
// dashboard clients render explanations from. They assert three guarantees:
// every blocking condition resolves to a *specific* reason (never a generic
// failure), the pre-flight reason always agrees with the error the real
// state-changing call reverts with, and the reason ⇄ code mapping is total
// and stable.

/// Initializes a contract with an AssetManager (`user1`), both users
/// whitelisted, and `user1` funded — the common baseline for restriction
/// tests, from which each test removes exactly one precondition.
fn setup_transferable() -> (Env, AegisContractClient<'static>, Address, Address, Address) {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);

    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user1, &1_000);

    (env, client, admin, user1, user2)
}

/// Asserts that a pre-flight restriction check and the real `transfer` call
/// agree: the reason returned by the read maps to exactly the error code the
/// state-changing call reverts with. This is the core contract that lets a
/// dashboard explain a failure it only observed as `Error(Contract, #code)`.
fn assert_transfer_blocked_by(
    client: &AegisContractClient<'static>,
    from: &Address,
    to: &Address,
    amount: &i128,
    expected_reason: RestrictionReason,
    expected_error: Error,
) {
    let reason = client.check_transfer_restriction(from, to, amount);
    assert_eq!(reason, expected_reason);
    assert_eq!(client.get_restriction_code(&reason), expected_error as u32);
    assert_eq!(
        client.try_transfer(from, to, amount),
        Err(Ok(expected_error))
    );
}

#[test]
fn test_unrestricted_transfer_reports_no_reason() {
    let (_env, client, _admin, user1, user2) = setup_transferable();

    let reason = client.check_transfer_restriction(&user1, &user2, &100);
    assert_eq!(reason, RestrictionReason::None);
    // `None` is the only reason with no error code.
    assert_eq!(client.get_restriction_code(&reason), 0);

    client.transfer(&user1, &user2, &100);
    assert_eq!(client.get_balance_of(&user2), 100);
}

#[test]
fn test_restriction_reason_non_compliant_sender() {
    let (_env, client, admin, user1, user2) = setup_transferable();

    client.revoke_whitelist(&admin, &user1);

    assert_transfer_blocked_by(
        &client,
        &user1,
        &user2,
        &100,
        RestrictionReason::SenderNotCompliant,
        Error::SenderNotWhitelisted,
    );
}

#[test]
fn test_restriction_reason_non_compliant_recipient() {
    let (env, client, _admin, user1, _user2) = setup_transferable();
    let outsider = Address::generate(&env);

    assert_transfer_blocked_by(
        &client,
        &user1,
        &outsider,
        &100,
        RestrictionReason::RecipientNotCompliant,
        Error::ReceiverNotWhitelisted,
    );
}

#[test]
fn test_restriction_reason_sender_checked_before_recipient() {
    // Both parties non-compliant: the reported reason must be deterministic
    // and match the on-chain check order, or a dashboard would show a
    // different explanation than the eventual revert.
    let (env, client, admin, user1, _user2) = setup_transferable();
    let outsider = Address::generate(&env);
    client.revoke_whitelist(&admin, &user1);

    assert_transfer_blocked_by(
        &client,
        &user1,
        &outsider,
        &100,
        RestrictionReason::SenderNotCompliant,
        Error::SenderNotWhitelisted,
    );
}

#[test]
fn test_restriction_reason_paused_asset() {
    let (_env, client, admin, user1, user2) = setup_transferable();

    client.set_asset_status(&admin, &AssetStatus::Paused);

    assert_transfer_blocked_by(
        &client,
        &user1,
        &user2,
        &100,
        RestrictionReason::AssetPaused,
        Error::AssetPausedRestriction,
    );

    // A paused asset is a *temporary* restriction — clients may offer retry.
    assert!(!client
        .check_transfer_restriction(&user1, &user2, &100)
        .is_terminal());

    // ...and the restriction lifts when the asset returns to Active.
    client.set_asset_status(&admin, &AssetStatus::Active);
    assert_eq!(
        client.check_transfer_restriction(&user1, &user2, &100),
        RestrictionReason::None
    );
    client.transfer(&user1, &user2, &100);
}

#[test]
fn test_restriction_reason_retired_asset() {
    let (_env, client, admin, user1, user2) = setup_transferable();

    client.set_asset_status(&admin, &AssetStatus::Retired);

    assert_transfer_blocked_by(
        &client,
        &user1,
        &user2,
        &100,
        RestrictionReason::AssetRetired,
        Error::AssetRetiredRestriction,
    );

    // Retirement is terminal: no later ledger state can unblock it.
    assert!(client
        .check_transfer_restriction(&user1, &user2, &100)
        .is_terminal());
    assert_eq!(
        client.try_set_asset_status(&admin, &AssetStatus::Active),
        Err(Ok(Error::InvalidLifecycleTransition))
    );
}

#[test]
fn test_restriction_reason_blocked_asset_is_distinct_from_paused_and_retired() {
    let (_env, client, admin, user1, user2) = setup_transferable();

    client.set_asset_status(&admin, &AssetStatus::Blocked);

    assert_transfer_blocked_by(
        &client,
        &user1,
        &user2,
        &100,
        RestrictionReason::AssetBlocked,
        Error::AssetBlockedRestriction,
    );

    // The three asset-state restrictions must not collapse into one code —
    // that collapse (the old generic `AssetNotActive`) is the bug this fixes.
    assert_ne!(
        Error::AssetBlockedRestriction as u32,
        Error::AssetPausedRestriction as u32
    );
    assert_ne!(
        Error::AssetBlockedRestriction as u32,
        Error::AssetRetiredRestriction as u32
    );
    assert_ne!(
        Error::AssetPausedRestriction as u32,
        Error::AssetRetiredRestriction as u32
    );
}

#[test]
fn test_restriction_reason_contract_pause_outranks_asset_state() {
    let (_env, client, admin, user1, user2) = setup_transferable();

    client.set_asset_status(&admin, &AssetStatus::Paused);
    client.pause(&admin);

    // The global emergency pause is evaluated first, so it — not the asset
    // status — is the reason reported, matching the revert.
    assert_transfer_blocked_by(
        &client,
        &user1,
        &user2,
        &100,
        RestrictionReason::ContractPaused,
        Error::ContractPaused,
    );
}

#[test]
fn test_restriction_reason_unauthorised_operation_on_mint() {
    let (_env, client, _admin, _user1, user2) = setup_transferable();

    // `user2` is whitelisted but holds no AssetManager role.
    let reason = client.check_mint_restriction(&user2, &user2, &100);
    assert_eq!(reason, RestrictionReason::UnauthorizedOperation);
    assert_eq!(
        client.get_restriction_code(&reason),
        Error::Unauthorized as u32
    );
    assert_eq!(
        client.try_mint_asset(&user2, &user2, &100),
        Err(Ok(Error::Unauthorized))
    );

    // An authorised caller reports no restriction for the same movement.
    assert_eq!(
        client.check_mint_restriction(&_user1, &user2, &100),
        RestrictionReason::None
    );
}

#[test]
fn test_restriction_reason_invalid_amount_and_insufficient_balance() {
    let (_env, client, _admin, user1, user2) = setup_transferable();

    assert_transfer_blocked_by(
        &client,
        &user1,
        &user2,
        &0,
        RestrictionReason::InvalidAmount,
        Error::InvalidAmount,
    );
    assert_transfer_blocked_by(
        &client,
        &user1,
        &user2,
        &-5,
        RestrictionReason::InvalidAmount,
        Error::InvalidAmount,
    );
    assert_transfer_blocked_by(
        &client,
        &user1,
        &user2,
        &100_000,
        RestrictionReason::InsufficientBalance,
        Error::InsufficientBalance,
    );
}

#[test]
fn test_restriction_reason_holding_cap_exceeded_on_transfer() {
    let (_env, client, admin, user1, user2) = setup_transferable();

    client.propose_holding_cap(&admin, &50);
    client.accept_holding_cap(&admin);

    // Previously a bare host panic with a string message; now a typed code.
    assert_transfer_blocked_by(
        &client,
        &user1,
        &user2,
        &100,
        RestrictionReason::HoldingCapExceeded,
        Error::HoldingCapExceeded,
    );

    // Within the cap, the same transfer is unrestricted.
    assert_eq!(
        client.check_transfer_restriction(&user1, &user2, &50),
        RestrictionReason::None
    );
    client.transfer(&user1, &user2, &50);
}

#[test]
fn test_restriction_reason_supply_cap_exceeded_on_mint() {
    let (_env, client, admin, user1, user2) = setup_transferable();

    // Total supply is already 1_000 from the baseline mint.
    client.propose_supply_cap(&admin, &1_100);
    client.accept_supply_cap(&admin);

    let reason = client.check_mint_restriction(&user1, &user2, &500);
    assert_eq!(reason, RestrictionReason::SupplyCapExceeded);
    assert_eq!(
        client.get_restriction_code(&reason),
        Error::SupplyCapExceeded as u32
    );
    assert_eq!(
        client.try_mint_asset(&user1, &user2, &500),
        Err(Ok(Error::SupplyCapExceeded))
    );

    assert_eq!(
        client.check_mint_restriction(&user1, &user2, &100),
        RestrictionReason::None
    );
    client.mint_asset(&user1, &user2, &100);
}

#[test]
fn test_restriction_reasons_on_mint_cover_compliance_and_asset_state() {
    let (env, client, admin, user1, user2) = setup_transferable();
    let outsider = Address::generate(&env);

    assert_eq!(
        client.check_mint_restriction(&user1, &outsider, &100),
        RestrictionReason::RecipientNotCompliant
    );
    assert_eq!(
        client.try_mint_asset(&user1, &outsider, &100),
        Err(Ok(Error::ReceiverNotWhitelisted))
    );

    client.set_asset_status(&admin, &AssetStatus::Paused);
    assert_eq!(
        client.check_mint_restriction(&user1, &user2, &100),
        RestrictionReason::AssetPaused
    );
    assert_eq!(
        client.try_mint_asset(&user1, &user2, &100),
        Err(Ok(Error::AssetPausedRestriction))
    );

    client.set_asset_status(&admin, &AssetStatus::Retired);
    assert_eq!(
        client.check_mint_restriction(&user1, &user2, &100),
        RestrictionReason::AssetRetired
    );
    assert_eq!(
        client.try_mint_asset(&user1, &user2, &100),
        Err(Ok(Error::AssetRetiredRestriction))
    );
}

#[test]
fn test_restriction_reason_code_mapping_is_total_and_round_trips() {
    let (_env, client, _admin, _user1, _user2) = setup();

    // Every reason a client can be handed must have a defined code, and every
    // blocking code must map back to the reason it came from. A gap here means
    // an SDK would fall through to a generic "transaction failed".
    let reasons = [
        (RestrictionReason::None, 0u32),
        (RestrictionReason::UnauthorizedOperation, 3000),
        (RestrictionReason::ContractPaused, 3004),
        (RestrictionReason::SenderNotCompliant, 4000),
        (RestrictionReason::RecipientNotCompliant, 4001),
        (RestrictionReason::InvalidAmount, 5000),
        (RestrictionReason::InsufficientBalance, 5001),
        (RestrictionReason::AssetPaused, 7000),
        (RestrictionReason::AssetRetired, 7001),
        (RestrictionReason::AssetBlocked, 7002),
        (RestrictionReason::SupplyCapExceeded, 5002),
        (RestrictionReason::HoldingCapExceeded, 5003),
    ];

    for (reason, expected_code) in reasons.iter() {
        // Codes agree between the pure helper and the on-chain entrypoint.
        assert_eq!(code_for_reason(reason), *expected_code);
        assert_eq!(client.get_restriction_code(reason), *expected_code);

        match error_for_reason(reason) {
            Some(err) => {
                assert!(reason.is_blocked());
                assert_eq!(err as u32, *expected_code);
                // Round-trip: code → error → reason recovers the original.
                assert_eq!(reason_for_error(&err), Some(*reason));
            }
            None => {
                assert_eq!(*reason, RestrictionReason::None);
                assert!(!reason.is_blocked());
            }
        }
    }

    // Non-restriction errors must NOT be rendered as blocked-transfer reasons.
    assert_eq!(reason_for_error(&Error::AlreadyInitialized), None);
    assert_eq!(reason_for_error(&Error::NotInitialized), None);
    assert_eq!(reason_for_error(&Error::InvalidAssetStatusTransition), None);
}

#[test]
fn test_restriction_checks_are_pure_reads_and_survive_paused_state() {
    let (_env, client, admin, user1, user2) = setup_transferable();

    let supply_before = client.get_total_supply();
    let balance_before = client.get_balance_of(&user1);

    client.pause(&admin);

    // Read helpers stay callable while paused and never mutate state.
    assert_eq!(
        client.check_transfer_restriction(&user1, &user2, &100),
        RestrictionReason::ContractPaused
    );
    assert_eq!(
        client.check_mint_restriction(&user1, &user2, &100),
        RestrictionReason::ContractPaused
    );
    assert_eq!(client.get_restriction_schema_version(), 1);

    assert_eq!(client.get_total_supply(), supply_before);
    assert_eq!(client.get_balance_of(&user1), balance_before);
    assert_eq!(client.get_balance_of(&user2), 0);
}

#[test]
fn test_restriction_checks_never_panic_on_uninitialized_contract() {
    let (env, client, _admin, user1, user2) = setup();

    // No `initialize`, no admin in storage: the reads must fail safe with a
    // reason rather than trapping, so a dashboard can render an explanation
    // against a fresh or misconfigured deployment. Asset lifecycle is
    // checked before sender compliance (see `evaluate_transfer`'s documented
    // order), and an unset asset status defaults to `Draft`, which maps to
    // `AssetBlocked` — so that's the first reason reported, not compliance.
    assert_eq!(
        client.check_transfer_restriction(&user1, &user2, &100),
        RestrictionReason::AssetBlocked
    );
    assert_eq!(
        client.check_mint_restriction(&user1, &user2, &100),
        RestrictionReason::UnauthorizedOperation
    );
    let _ = env;
}

#[test]
fn test_blocked_transfers_leave_no_state_change_and_emit_no_event() {
    let (env, client, admin, user1, user2) = setup_transferable();

    client.set_asset_status(&admin, &AssetStatus::Blocked);

    let supply_before = client.get_total_supply();
    let from_before = client.get_balance_of(&user1);
    let to_before = client.get_balance_of(&user2);
    let events_before = env.events().all();

    assert_eq!(
        client.try_transfer(&user1, &user2, &100),
        Err(Ok(Error::AssetBlockedRestriction))
    );

    assert_eq!(client.get_total_supply(), supply_before);
    assert_eq!(client.get_balance_of(&user1), from_before);
    assert_eq!(client.get_balance_of(&user2), to_before);
    // Soroban discards events from reverted invocations — the error code is
    // the only off-chain signal, which is exactly why it must be specific.
    assert_eq!(env.events().all(), events_before);
}

#[test]
fn test_restriction_reason_agrees_with_check_transfer_eligibility() {
    let (env, client, admin, user1, user2) = setup_transferable();
    let outsider = Address::generate(&env);

    // The boolean helper and the reason helper must never disagree: the
    // reason is the strictly more informative form of the same verdict.
    let cases: [(Address, Address, i128); 5] = [
        (user1.clone(), user2.clone(), 100),
        (user1.clone(), outsider.clone(), 100),
        (outsider.clone(), user2.clone(), 100),
        (user1.clone(), user2.clone(), 0),
        (user1.clone(), user2.clone(), 100_000),
    ];
    for (from, to, amount) in cases.iter() {
        let eligible = client.check_transfer_eligibility(from, to, amount);
        let reason = client.check_transfer_restriction(from, to, amount);
        assert_eq!(eligible, !reason.is_blocked());
    }

    // ...including under a lifecycle restriction.
    client.set_asset_status(&admin, &AssetStatus::Retired);
    assert!(!client.check_transfer_eligibility(&user1, &user2, &100));
    assert!(client
        .check_transfer_restriction(&user1, &user2, &100)
        .is_blocked());
}

#[test]
fn test_investor_eligibility_snapshot_agrees_with_restriction_reasons() {
    let (_env, client, admin, user1, user2) = setup_transferable();

    // The aggregated investor snapshot and the per-movement reason must tell
    // the same story, so a dashboard cannot show "eligible" next to a
    // blocked-transfer explanation.
    let snapshot: InvestorEligibility = client.get_investor_eligibility(&user1);
    assert!(snapshot.whitelisted);
    assert!(snapshot.can_send);
    assert!(!snapshot.contract_paused);
    assert_eq!(
        client.check_transfer_restriction(&user1, &user2, &100),
        RestrictionReason::None
    );

    // Revoking compliance must flip both views together.
    client.revoke_whitelist(&admin, &user1);
    let snapshot = client.get_investor_eligibility(&user1);
    assert!(!snapshot.whitelisted);
    assert!(!snapshot.can_send);
    assert_eq!(
        client.check_transfer_restriction(&user1, &user2, &100),
        RestrictionReason::SenderNotCompliant
    );

    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user2);
    client.propose_holding_cap(&admin, &500);
    client.accept_holding_cap(&admin);

    // Partially filled: headroom remains, so the investor can still receive.
    client.mint_asset(&user1, &user2, &300);
    let elig = client.get_investor_eligibility(&user2);
    assert_eq!(elig.holding_cap, 500);
    assert_eq!(elig.remaining_capacity, Some(200));
    assert!(elig.can_receive);
    assert!(elig.can_send);

    // Filled to the cap: no headroom left, so the investor cannot receive
    // further tokens, but can still send out of their existing balance.
    client.mint_asset(&user1, &user2, &200);
    let elig = client.get_investor_eligibility(&user2);
    assert_eq!(elig.balance, 500);
    assert_eq!(elig.remaining_capacity, Some(0));
    assert!(!elig.can_receive);
    assert!(elig.can_send);
}

#[test]
fn test_eligibility_reflects_paused_contract() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user2, &500);

    client.pause(&admin);

    // The read helper itself must remain callable while paused...
    let elig = client.get_investor_eligibility(&user2);
    // ...but reflects that no transfer/mint can currently succeed.
    assert!(elig.whitelisted);
    assert!(elig.contract_paused);
    assert_eq!(elig.balance, 500);
    assert!(!elig.can_receive);
    assert!(!elig.can_send);
}

#[test]
fn test_check_transfer_eligibility_true_for_eligible_transfer() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user1, &1000);

    assert!(client.check_transfer_eligibility(&user1, &user2, &250));

    // The check does not mutate state: the actual transfer still succeeds
    // afterwards for the same amount.
    let result = client.try_transfer(&user1, &user2, &250);
    assert!(result.is_ok());
}

#[test]
fn test_check_transfer_eligibility_false_when_invalid_amount() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    // Before initialize — no auth mocked, no admin in storage.
    assert_eq!(
        client.supports_capability(&soroban_sdk::Symbol::new(&env, "whitelist")),
        CapabilityStatus::Supported
    );
    assert_eq!(client.get_capability_keys().len(), 34);

    client.initialize(&admin);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);

    assert!(!client.check_transfer_eligibility(&user1, &user2, &0));
    assert!(!client.check_transfer_eligibility(&user1, &user2, &-10));
}

#[test]
fn test_check_transfer_eligibility_false_when_sender_not_whitelisted() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.whitelist_user(&admin, &user2);
    // user1 was never whitelisted.

    assert!(!client.check_transfer_eligibility(&user1, &user2, &100));
}

#[test]
fn test_check_transfer_eligibility_false_when_receiver_not_whitelisted() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.whitelist_user(&admin, &user1);
    // user2 was never whitelisted.

    assert!(!client.check_transfer_eligibility(&user1, &user2, &100));
}

#[test]
fn test_check_transfer_eligibility_false_when_insufficient_balance() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user1, &50);

    // user1 only has a balance of 50.
    assert!(!client.check_transfer_eligibility(&user1, &user2, &100));
}

#[test]
fn test_check_transfer_eligibility_false_when_over_holding_cap() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user1, &1000);

    client.propose_holding_cap(&admin, &300);
    client.accept_holding_cap(&admin);

    // Would push user2 over the 300 cap.
    assert!(!client.check_transfer_eligibility(&user1, &user2, &301));
    // Exactly at the cap is still eligible.
    assert!(client.check_transfer_eligibility(&user1, &user2, &300));
}

#[test]
fn test_check_transfer_eligibility_false_when_contract_paused() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user1, &1000);

    client.pause(&admin);

    // And while paused.
    assert_eq!(
        client.supports_capability(&soroban_sdk::Symbol::new(&env, "whitelist")),
        CapabilityStatus::Supported
    );
    assert_eq!(client.get_capability_keys().len(), 34);

    // The read helper itself must remain callable while paused, but must
    // reflect that transfers cannot currently succeed.
    assert!(!client.check_transfer_eligibility(&user1, &user2, &100));
}

#[test]
fn test_check_transfer_eligibility_matches_actual_transfer_outcomes() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.mint_asset(&user1, &user1, &1000);
    // user2 deliberately left off the whitelist.

    assert!(!client.check_transfer_eligibility(&user1, &user2, &100));
    let result = client.try_transfer(&user1, &user2, &100);
    assert_eq!(result, Err(Ok(Error::ReceiverNotWhitelisted)));
}

// ─── Supply cap error standardization (#32) ────────────────────────────────────

#[test]
fn test_supply_cap_exceeded_returns_standardized_error() {
    let (env, client, admin, _user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.whitelist_user(&admin, &user2);
    client.propose_supply_cap(&admin, &100);
    client.accept_supply_cap(&admin);

    // Reach the cap exactly.
    client.mint_asset(&admin, &user2, &100);
    assert_eq!(client.get_total_supply(), 100);

    // Any mint beyond cap must return the standardized error code.
    let r = client.try_mint_asset(&admin, &user2, &1);
    assert_eq!(r, Err(Ok(Error::SupplyCapExceeded)));
}

#[test]
fn test_holding_cap_exceeded_returns_standardized_error() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&user1, &user1, &500);
    client.propose_holding_cap(&admin, &300);
    client.accept_holding_cap(&admin);

    // Transfer that pushes receiver over cap must return the standardized error.
    let r = client.try_transfer(&user1, &user2, &301);
    assert_eq!(r, Err(Ok(Error::HoldingCapExceeded)));
}

// ─── Supply cap event compatibility (#32) ─────────────────────────────────────

#[test]
fn test_supply_cap_proposed_and_amended_emit_events() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.propose_supply_cap(&admin, &500);

    // Propose event
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("supply_cap_proposed",).into_val(&env),
                crate::supply_cap::SupplyCapProposedEvent {
                    admin: admin.clone(),
                    current_cap: 0,
                    proposed_cap: 500,
                }
                .into_val(&env),
            ),
        ]
    );

    client.accept_supply_cap(&admin);

    // Amended event
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("supply_cap_amended",).into_val(&env),
                crate::supply_cap::SupplyCapAmendedEvent {
                    admin: admin.clone(),
                    previous_cap: 0,
                    new_cap: 500,
                }
                .into_val(&env),
            ),
        ]
    );
}

// ─── COMPLIANCE STATUS TRANSITION INVARIANTS (Audit Readiness) ────────────────
//
// Deterministic invariant coverage for compliance status transitions. The
// full model — statuses, transition matrix, authorization rules, the blocked
// overlay, event guarantees, and consistency invariants — is documented in
// docs/compliance-status-transitions.md.
//
// The compliance registry is an address-keyed set (see
// docs/compliance-registry-reads.md), so an investor's *compliance status* is
// derived from observable contract state plus the transition history of the
// address:
//
// | Status    | How the address got there                          | is_whitelisted |
// |-----------|----------------------------------------------------|----------------|
// | Unknown   | never targeted by any compliance call              | false          |
// | Pending   | an approval attempt was rejected (still waiting)   | false          |
// | Approved  | a committed `whitelist_user`                       | true           |
// | Revoked   | a committed `revoke_whitelist` after Approved      | false          |
//
// "Blocked" is a global overlay rather than a per-address status: while the
// contract is paused, EVERY compliance transition attempt reverts with
// `ContractPaused`, regardless of address status or caller.
//
// Every matrix row runs against a fresh contract deployment, so results
// depend only on the row's (status, action, caller) triple — never on test
// execution order.

/// The compliance statuses an investor address can be in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LegacyComplianceStatus {
    /// No record: the address has never been targeted by a compliance call.
    Unknown,
    /// Awaiting approval: an earlier approval attempt was rejected (wrong
    /// caller or paused contract), so the address is still off the whitelist.
    Pending,
    /// On the whitelist: may receive and send assets.
    Approved,
    /// Removed from the whitelist after having been approved.
    Revoked,
}

impl LegacyComplianceStatus {
    const ALL: [LegacyComplianceStatus; 4] = [
        LegacyComplianceStatus::Unknown,
        LegacyComplianceStatus::Pending,
        LegacyComplianceStatus::Approved,
        LegacyComplianceStatus::Revoked,
    ];

    /// The whitelist flag observable on-chain for an address in this status.
    fn is_approved(self) -> bool {
        matches!(self, LegacyComplianceStatus::Approved)
    }
}

/// The two compliance transitions the contract exposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ComplianceAction {
    /// `whitelist_user` — drives an address towards `Approved`.
    Approve,
    /// `revoke_whitelist` — drives an address towards `Revoked`.
    Revoke,
}

impl ComplianceAction {
    const ALL: [ComplianceAction; 2] = [ComplianceAction::Approve, ComplianceAction::Revoke];

    /// The whitelist flag this action commits on success.
    fn result_is_approved(self) -> bool {
        matches!(self, ComplianceAction::Approve)
    }
}

/// Caller classes exercised against the transition matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransitionCaller {
    /// The supreme admin — bypasses role checks.
    Admin,
    /// Compliance-scoped role — manages the whitelist.
    ComplianceOfficer,
    /// Combined compliance + asset role — also manages the whitelist.
    EmergencyOfficer,
    /// No role at all — must always be rejected.
    NoRole,
    /// A real but wrong-scoped role — must always be rejected.
    AssetManager,
}

impl TransitionCaller {
    const ALL: [TransitionCaller; 5] = [
        TransitionCaller::Admin,
        TransitionCaller::ComplianceOfficer,
        TransitionCaller::EmergencyOfficer,
        TransitionCaller::NoRole,
        TransitionCaller::AssetManager,
    ];

    fn is_authorised(self) -> bool {
        matches!(
            self,
            TransitionCaller::Admin
                | TransitionCaller::ComplianceOfficer
                | TransitionCaller::EmergencyOfficer
        )
    }
}

/// Normalized result of a compliance transition attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransitionOutcome {
    /// The transition committed; state and events were written.
    Committed,
    /// The contract rejected the transition with a standardized error code.
    Rejected(Error),
    /// Any other abort (host error) — never expected in these tests.
    Aborted,
}

/// A fresh deployment wired with the named actors the matrix needs.
struct ComplianceFixture {
    env: Env,
    client: AegisContractClient<'static>,
    admin: Address,
    officer: Address,
    emergency: Address,
    manager: Address,
    intruder: Address,
    target: Address,
}

impl ComplianceFixture {
    fn new() -> Self {
        let env = Env::default();
        let contract_id = env.register(AegisContract, ());
        let client = AegisContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let officer = Address::generate(&env);
        let emergency = Address::generate(&env);
        let manager = Address::generate(&env);
        let intruder = Address::generate(&env);
        let target = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);
        client.set_asset_status(&admin, &AssetStatus::Active);
        client.set_role(&admin, &officer, &Role::ComplianceOfficer);
        client.set_role(&admin, &emergency, &Role::EmergencyOfficer);
        client.set_role(&admin, &manager, &Role::AssetManager);

        Self {
            env,
            client,
            admin,
            officer,
            emergency,
            manager,
            intruder,
            target,
        }
    }

    fn caller_address(&self, caller: TransitionCaller) -> Address {
        match caller {
            TransitionCaller::Admin => self.admin.clone(),
            TransitionCaller::ComplianceOfficer => self.officer.clone(),
            TransitionCaller::EmergencyOfficer => self.emergency.clone(),
            TransitionCaller::NoRole => self.intruder.clone(),
            TransitionCaller::AssetManager => self.manager.clone(),
        }
    }

    fn is_target_approved(&self) -> bool {
        self.client.is_whitelisted(&self.target)
    }

    /// Events observed from the most recent top-level invocation.
    fn last_invocation_event_count(&self) -> usize {
        self.env.events().all().events().len()
    }

    /// Drives `target` into `status` using committed transitions — plus, for
    /// `Pending`, one rejected approval attempt by an unauthorised caller.
    fn drive_to_status(&self, status: LegacyComplianceStatus) {
        match status {
            LegacyComplianceStatus::Unknown => {}
            LegacyComplianceStatus::Pending => {
                let outcome = self.attempt(ComplianceAction::Approve, TransitionCaller::NoRole);
                assert_eq!(outcome, TransitionOutcome::Rejected(Error::Unauthorized));
            }
            LegacyComplianceStatus::Approved => {
                self.client.whitelist_user(&self.officer, &self.target);
            }
            LegacyComplianceStatus::Revoked => {
                self.client.whitelist_user(&self.officer, &self.target);
                self.client.revoke_whitelist(&self.officer, &self.target);
            }
        }
        assert_eq!(
            self.is_target_approved(),
            status.is_approved(),
            "fixture failed to reach {status:?}"
        );
    }

    /// Attempts `action` on `target` as `caller`, normalizing the result.
    fn attempt(&self, action: ComplianceAction, caller: TransitionCaller) -> TransitionOutcome {
        let caller = self.caller_address(caller);
        let result = match action {
            ComplianceAction::Approve => self.client.try_whitelist_user(&caller, &self.target),
            ComplianceAction::Revoke => self.client.try_revoke_whitelist(&caller, &self.target),
        };
        match result {
            Ok(Ok(())) => TransitionOutcome::Committed,
            Err(Ok(e)) => TransitionOutcome::Rejected(e),
            _ => TransitionOutcome::Aborted,
        }
    }
}

#[test]
fn test_compliance_transition_matrix_deterministic() {
    // The deterministic transition matrix: every (status, action, caller)
    // combination against a fresh deployment.
    //
    // Authorised callers: every transition commits and the final status is
    // exactly the action's target — Approve always lands on Approved
    // (idempotent re-approval) and Revoke always lands off the whitelist
    // (idempotent no-op for Unknown/Pending/Revoked).
    //
    // Unauthorised callers: every transition is rejected with `Unauthorized`
    // and the address status is left exactly as it was — invalid transitions
    // cannot create a bypass.
    for status in LegacyComplianceStatus::ALL {
        for action in ComplianceAction::ALL {
            for caller in TransitionCaller::ALL {
                let fixture = ComplianceFixture::new();
                fixture.drive_to_status(status);
                let before = fixture.is_target_approved();

                let outcome = fixture.attempt(action, caller);

                if caller.is_authorised() {
                    assert_eq!(
                        outcome,
                        TransitionOutcome::Committed,
                        "{status:?} + {action:?} by {caller:?} must commit"
                    );
                    assert_eq!(
                        fixture.is_target_approved(),
                        action.result_is_approved(),
                        "wrong final status: {status:?} + {action:?} by {caller:?}"
                    );
                } else {
                    assert_eq!(
                        outcome,
                        TransitionOutcome::Rejected(Error::Unauthorized),
                        "{status:?} + {action:?} by {caller:?} must be Unauthorized"
                    );
                    assert_eq!(
                        fixture.is_target_approved(),
                        before,
                        "unauthorised {action:?} changed status {status:?} for {caller:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn test_compliance_transitions_blocked_when_paused() {
    // The blocked overlay: while paused, EVERY transition attempt — from any
    // status, with any action, by any caller, authorised or not — reverts
    // with `ContractPaused`, because the pause guard runs before role checks.
    // No event escapes a blocked transition and the address status is left
    // unchanged. After unpause, authorised transitions work again, so the
    // blocked overlay never becomes a permanent lockout.
    for status in LegacyComplianceStatus::ALL {
        for action in ComplianceAction::ALL {
            for caller in TransitionCaller::ALL {
                let fixture = ComplianceFixture::new();
                fixture.drive_to_status(status);
                fixture.client.pause(&fixture.admin);
                let before = fixture.is_target_approved();

                let outcome = fixture.attempt(action, caller);

                assert_eq!(
                    outcome,
                    TransitionOutcome::Rejected(Error::ContractPaused),
                    "blocked {action:?} from {status:?} by {caller:?} must report ContractPaused"
                );
                assert_eq!(
                    fixture.is_target_approved(),
                    before,
                    "blocked {action:?} changed status {status:?} for {caller:?}"
                );
                assert_eq!(
                    fixture.last_invocation_event_count(),
                    0,
                    "blocked {action:?} from {status:?} by {caller:?} emitted an event"
                );

                // Unpause: the same transition now resolves by caller class.
                fixture.client.unpause(&fixture.admin);
                let outcome = fixture.attempt(action, caller);
                if caller.is_authorised() {
                    assert_eq!(
                        outcome,
                        TransitionOutcome::Committed,
                        "post-unpause {action:?} by {caller:?} must commit"
                    );
                    assert_eq!(
                        fixture.is_target_approved(),
                        action.result_is_approved(),
                        "post-unpause final status wrong: {status:?} + {action:?} by {caller:?}"
                    );
                } else {
                    assert_eq!(
                        outcome,
                        TransitionOutcome::Rejected(Error::Unauthorized),
                        "post-unpause {action:?} by {caller:?} must be Unauthorized"
                    );
                    assert_eq!(
                        fixture.is_target_approved(),
                        before,
                        "post-unpause unauthorised {action:?} changed state for {caller:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn test_compliance_transition_events_have_exact_shape() {
    let fixture = ComplianceFixture::new();

    // Approve by a role caller (not the admin): the `caller` field must
    // record the officer, proving the event tracks the actual authorizer.
    fixture
        .client
        .whitelist_user(&fixture.officer, &fixture.target);
    assert_eq!(
        fixture.env.events().all(),
        vec![
            &fixture.env,
            (
                fixture.client.address.clone(),
                ("compliance_status_changed",).into_val(&fixture.env),
                ComplianceStatusChangedEvent {
                    caller: fixture.officer.clone(),
                    user: fixture.target.clone(),
                    previous_status: ComplianceStatus::Unknown,
                    new_status: ComplianceStatus::Approved,
                }
                .into_val(&fixture.env),
            ),
            (
                fixture.client.address.clone(),
                ("user_whitelisted",).into_val(&fixture.env),
                UserWhitelistedEvent {
                    caller: fixture.officer.clone(),
                    user: fixture.target.clone(),
                }
                .into_val(&fixture.env),
            ),
        ]
    );

    // Revoke by the emergency officer: same caller-tracking guarantee.
    fixture
        .client
        .revoke_whitelist(&fixture.emergency, &fixture.target);

    assert_eq!(
        fixture.env.events().all(),
        vec![
            &fixture.env,
            (
                fixture.client.address.clone(),
                ("compliance_status_changed",).into_val(&fixture.env),
                ComplianceStatusChangedEvent {
                    caller: fixture.emergency.clone(),
                    user: fixture.target.clone(),
                    previous_status: ComplianceStatus::Approved,
                    new_status: ComplianceStatus::Revoked,
                }
                .into_val(&fixture.env),
            ),
            (
                fixture.client.address.clone(),
                ("whitelist_revoked",).into_val(&fixture.env),
                WhitelistRevokedEvent {
                    caller: fixture.emergency.clone(),
                    user: fixture.target.clone(),
                }
                .into_val(&fixture.env),
            ),
        ]
    );
}

#[test]
fn test_rejected_compliance_transitions_emit_no_events() {
    let fixture = ComplianceFixture::new();
    fixture
        .client
        .whitelist_user(&fixture.officer, &fixture.target);
    let outsider = Address::generate(&fixture.env);

    // Unauthorised revoke of an approved address.
    let outcome = fixture.attempt(ComplianceAction::Revoke, TransitionCaller::NoRole);
    assert_eq!(outcome, TransitionOutcome::Rejected(Error::Unauthorized));
    assert_eq!(fixture.last_invocation_event_count(), 0);

    // Wrong-scope role approving a new address.
    let result = fixture
        .client
        .try_whitelist_user(&fixture.manager, &outsider);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));
    assert_eq!(fixture.last_invocation_event_count(), 0);

    // Paused (blocked) transitions of both kinds.
    fixture.client.pause(&fixture.admin);
    let outcome = fixture.attempt(
        ComplianceAction::Revoke,
        TransitionCaller::ComplianceOfficer,
    );
    assert_eq!(outcome, TransitionOutcome::Rejected(Error::ContractPaused));
    assert_eq!(fixture.last_invocation_event_count(), 0);

    let result = fixture.client.try_whitelist_user(&fixture.admin, &outsider);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
    assert_eq!(fixture.last_invocation_event_count(), 0);

    // Soroban also discards events from reverted invocations: neither the
    // approved target nor the untouched outsider changed status.
    assert!(fixture.is_target_approved());
    assert!(!fixture.client.is_whitelisted(&outsider));
}

#[test]
fn test_failed_compliance_transitions_leave_state_consistent() {
    let fixture = ComplianceFixture::new();
    let bystander = Address::generate(&fixture.env);
    let outsider = Address::generate(&fixture.env);

    // Seed realistic state worth protecting.
    fixture
        .client
        .whitelist_user(&fixture.officer, &fixture.target);
    fixture.client.whitelist_user(&fixture.officer, &bystander);
    fixture
        .client
        .mint_asset(&fixture.manager, &fixture.target, &700);
    fixture
        .client
        .mint_asset(&fixture.manager, &bystander, &300);

    // Snapshot every observable a failed transition could plausibly corrupt.
    let target_approved = fixture.is_target_approved();
    let bystander_approved = fixture.client.is_whitelisted(&bystander);
    let outsider_approved = fixture.client.is_whitelisted(&outsider);
    let target_balance = fixture.client.get_balance_of(&fixture.target);
    let bystander_balance = fixture.client.get_balance_of(&bystander);
    let total_supply = fixture.client.get_total_supply();
    let officer_role = fixture.client.get_role_of(&fixture.officer);
    let asset_status = fixture.client.get_asset_status();
    let paused = fixture.client.is_paused();

    // Wave 1: unauthorised callers of both kinds, both actions.
    for caller in [TransitionCaller::NoRole, TransitionCaller::AssetManager] {
        for action in ComplianceAction::ALL {
            let outcome = fixture.attempt(action, caller);
            assert_eq!(outcome, TransitionOutcome::Rejected(Error::Unauthorized));
            assert_eq!(fixture.last_invocation_event_count(), 0);
        }
    }
    let result = fixture
        .client
        .try_whitelist_user(&fixture.intruder, &outsider);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));
    let result = fixture
        .client
        .try_revoke_whitelist(&fixture.manager, &outsider);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    // Wave 2: the blocked overlay, both actions, authorised callers.
    fixture.client.pause(&fixture.admin);
    let outcome = fixture.attempt(
        ComplianceAction::Revoke,
        TransitionCaller::ComplianceOfficer,
    );
    assert_eq!(outcome, TransitionOutcome::Rejected(Error::ContractPaused));
    let result = fixture
        .client
        .try_whitelist_user(&fixture.emergency, &outsider);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
    fixture.client.unpause(&fixture.admin);

    // Nothing moved — every rejected transition was atomic, and failures
    // targeting one address never bled into a bystander's state.
    assert_eq!(fixture.is_target_approved(), target_approved);
    assert_eq!(
        fixture.client.is_whitelisted(&bystander),
        bystander_approved
    );
    assert_eq!(fixture.client.is_whitelisted(&outsider), outsider_approved);
    assert_eq!(
        fixture.client.get_balance_of(&fixture.target),
        target_balance
    );
    assert_eq!(fixture.client.get_balance_of(&bystander), bystander_balance);
    assert_eq!(fixture.client.get_total_supply(), total_supply);
    assert_eq!(fixture.client.get_role_of(&fixture.officer), officer_role);
    assert_eq!(fixture.client.get_asset_status(), asset_status);
    assert_eq!(fixture.client.is_paused(), paused);

    // The registry is not wedged by the failures: valid transitions still go
    // through for the same addresses.
    fixture
        .client
        .revoke_whitelist(&fixture.officer, &fixture.target);
    assert!(!fixture.is_target_approved());
    fixture.client.whitelist_user(&fixture.emergency, &outsider);
    assert!(fixture.client.is_whitelisted(&outsider));

    // Revocation freezes the account but never destroys its balance.
    assert_eq!(
        fixture.client.get_balance_of(&fixture.target),
        target_balance
    );
}

// ─── Holding cap event compatibility (#33) ───────────────────────────────────

#[test]
fn test_holding_cap_proposed_and_amended_emit_events() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();

    client.initialize(&admin);
    client.propose_holding_cap(&admin, &300);

    // Propose event
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("holding_cap_proposed",).into_val(&env),
                crate::holding::HoldingCapProposedEvent {
                    admin: admin.clone(),
                    current_cap: 0,
                    proposed_cap: 300,
                }
                .into_val(&env),
            ),
        ]
    );

    client.accept_holding_cap(&admin);

    // Amended event
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("holding_cap_amended",).into_val(&env),
                crate::holding::HoldingCapAmendedEvent {
                    admin: admin.clone(),
                    previous_cap: 0,
                    new_cap: 300,
                }
                .into_val(&env),
            ),
        ]
    );
}

// ─── Compliance lifecycle state machine (#compliance-lifecycle) ──────────────
//
// These tests lock down the five-state investor compliance lifecycle: the
// default state, every allowed transition, every rejected transition, the
// authorization asymmetry around `Blocked`, the events emitted on change, and
// the fact that minting and transfers actually consume the lifecycle state.

/// Every lifecycle state, in ABI order.
const ALL_STATUSES: [ComplianceStatus; 5] = [
    ComplianceStatus::Unknown,
    ComplianceStatus::Pending,
    ComplianceStatus::Approved,
    ComplianceStatus::Revoked,
    ComplianceStatus::Blocked,
];

/// The authoritative transition matrix, duplicated here on purpose: the test
/// must fail if `compliance.rs` ever silently widens or narrows it.
fn expected_allowed(from: ComplianceStatus, to: ComplianceStatus) -> bool {
    use ComplianceStatus::*;
    matches!(
        (from, to),
        (Unknown, Pending)
            | (Unknown, Approved)
            | (Unknown, Blocked)
            | (Pending, Approved)
            | (Pending, Revoked)
            | (Pending, Blocked)
            | (Approved, Pending)
            | (Approved, Revoked)
            | (Approved, Blocked)
            | (Revoked, Pending)
            | (Revoked, Approved)
            | (Revoked, Blocked)
            | (Blocked, Pending)
    )
}

#[test]
fn test_compliance_status_defaults_to_unknown() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();

    // Readable before initialize — a pure read with a fail-closed default.
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Unknown
    );

    client.initialize(&admin);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Unknown
    );
    // The legacy boolean is derived from the lifecycle, so it agrees.
    assert!(!client.is_whitelisted(&user1));
}

#[test]
fn test_transition_matrix_matches_specification() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    for from in ALL_STATUSES.iter() {
        for to in ALL_STATUSES.iter() {
            assert_eq!(
                client.is_compliance_transition_allowed(from, to),
                expected_allowed(*from, *to),
                "transition matrix drift"
            );
        }
    }
}

#[test]
fn test_self_transitions_are_never_allowed() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    for status in ALL_STATUSES.iter() {
        assert!(
            !client.is_compliance_transition_allowed(status, status),
            "a no-op must not be a valid transition"
        );
    }
}

#[test]
fn test_unknown_is_never_a_transition_target() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    // Compliance history is never erased — offboarding is `Revoked`.
    for from in ALL_STATUSES.iter() {
        assert!(!client.is_compliance_transition_allowed(from, &ComplianceStatus::Unknown));
    }
}

#[test]
fn test_get_allowed_transitions_lists_exactly_the_legal_targets() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    for from in ALL_STATUSES.iter() {
        let allowed = client.get_allowed_transitions(from);
        for to in ALL_STATUSES.iter() {
            assert_eq!(
                allowed.contains(to),
                expected_allowed(*from, *to),
                "allowed-transition list disagrees with the matrix"
            );
        }
    }

    // Blocked is a quarantine with exactly one exit.
    let from_blocked = client.get_allowed_transitions(&ComplianceStatus::Blocked);
    assert_eq!(from_blocked.len(), 1);
    assert_eq!(from_blocked.get(0).unwrap(), ComplianceStatus::Pending);
}

#[test]
fn test_get_allowed_transitions_for_address_tracks_current_state() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    // Unknown → three options.
    assert_eq!(client.get_allowed_transitions_for(&user1).len(), 3);

    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Blocked);
    let allowed = client.get_allowed_transitions_for(&user1);
    assert_eq!(allowed.len(), 1);
    assert_eq!(allowed.get(0).unwrap(), ComplianceStatus::Pending);
}

#[test]
fn test_full_happy_path_lifecycle_walk() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    // Unknown → Pending → Approved → Revoked → Approved → Blocked → Pending
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Pending);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Pending
    );
    assert!(!client.is_whitelisted(&user1));

    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Approved);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Approved
    );
    assert!(client.is_whitelisted(&user1));

    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Revoked);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Revoked
    );
    assert!(!client.is_whitelisted(&user1));

    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Approved);
    assert!(client.is_whitelisted(&user1));

    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Blocked);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Blocked
    );
    assert!(!client.is_whitelisted(&user1));

    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Pending);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Pending
    );
}

#[test]
fn test_batch_set_compliance_status_updates_many_addresses_atomically() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    let updates = vec![
        &env,
        ComplianceBatchUpdate {
            user: user1.clone(),
            new_status: ComplianceStatus::Pending,
        },
        ComplianceBatchUpdate {
            user: user2.clone(),
            new_status: ComplianceStatus::Approved,
        },
    ];

    let applied = client.batch_set_compliance_status(&admin, &updates);

    assert_eq!(applied, 2);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Pending
    );
    assert_eq!(
        client.get_compliance_status(&user2),
        ComplianceStatus::Approved
    );
    assert!(!client.is_whitelisted(&user1));
    assert!(client.is_whitelisted(&user2));
}

#[test]
fn test_batch_set_compliance_status_rejects_invalid_entry_without_partial_write() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Pending);

    let updates = vec![
        &env,
        ComplianceBatchUpdate {
            user: user1.clone(),
            new_status: ComplianceStatus::Approved,
        },
        ComplianceBatchUpdate {
            user: user2.clone(),
            new_status: ComplianceStatus::Revoked,
        },
    ];

    let result = client.try_batch_set_compliance_status(&admin, &updates);

    assert_eq!(result, Err(Ok(Error::InvalidComplianceTransition)));
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Pending
    );
    assert_eq!(
        client.get_compliance_status(&user2),
        ComplianceStatus::Unknown
    );
    assert_eq!(env.events().all().events().len(), 0);
}

#[test]
fn test_batch_set_compliance_status_rejects_duplicates_and_no_ops() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Pending);

    let duplicate_updates = vec![
        &env,
        ComplianceBatchUpdate {
            user: user1.clone(),
            new_status: ComplianceStatus::Pending,
        },
        ComplianceBatchUpdate {
            user: user1.clone(),
            new_status: ComplianceStatus::Approved,
        },
    ];
    assert_eq!(
        client.try_batch_set_compliance_status(&admin, &duplicate_updates),
        Err(Ok(Error::InvalidComplianceTransition))
    );
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Unknown
    );

    let no_op_updates = vec![
        &env,
        ComplianceBatchUpdate {
            user: user1.clone(),
            new_status: ComplianceStatus::Approved,
        },
        ComplianceBatchUpdate {
            user: user2.clone(),
            new_status: ComplianceStatus::Pending,
        },
    ];
    assert_eq!(
        client.try_batch_set_compliance_status(&admin, &no_op_updates),
        Err(Ok(Error::ComplianceStatusUnchanged))
    );
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Unknown
    );
    assert_eq!(
        client.get_compliance_status(&user2),
        ComplianceStatus::Pending
    );
}

#[test]
fn test_batch_set_compliance_status_handles_empty_and_paused_batches() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    let empty = vec![&env];
    assert_eq!(client.batch_set_compliance_status(&admin, &empty), 0);

    let updates = vec![
        &env,
        ComplianceBatchUpdate {
            user: user1.clone(),
            new_status: ComplianceStatus::Approved,
        },
    ];
    client.pause(&admin);

    assert_eq!(
        client.try_batch_set_compliance_status(&admin, &updates),
        Err(Ok(Error::ContractPaused))
    );
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Unknown
    );
}

#[test]
fn test_invalid_transitions_are_rejected_and_leave_state_unchanged() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    // Blocked → Approved is the headline rejection: a sanctions freeze can
    // only be lifted back into review, never straight to cleared.
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Blocked);
    let r = client.try_set_compliance_status(&admin, &user1, &ComplianceStatus::Approved);
    assert_eq!(r, Err(Ok(Error::InvalidComplianceTransition)));
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Blocked
    );

    // Blocked → Revoked is also rejected (would be a silent downgrade).
    let r = client.try_set_compliance_status(&admin, &user1, &ComplianceStatus::Revoked);
    assert_eq!(r, Err(Ok(Error::InvalidComplianceTransition)));
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Blocked
    );

    // Blocked → Unknown: history cannot be erased.
    let r = client.try_set_compliance_status(&admin, &user1, &ComplianceStatus::Unknown);
    assert_eq!(r, Err(Ok(Error::InvalidComplianceTransition)));
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Blocked
    );
}

#[test]
fn test_unknown_to_revoked_is_rejected() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    // Nothing has ever been granted, so there is nothing to revoke.
    let r = client.try_set_compliance_status(&admin, &user1, &ComplianceStatus::Revoked);
    assert_eq!(r, Err(Ok(Error::InvalidComplianceTransition)));
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Unknown
    );
}

#[test]
fn test_every_invalid_transition_is_rejected_exhaustively() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    for from in ALL_STATUSES.iter() {
        for to in ALL_STATUSES.iter() {
            if expected_allowed(*from, *to) {
                continue;
            }

            // Fresh address per case so each starts from a clean record and
            // is driven to `from` only through legal transitions.
            let subject = Address::generate(&env);
            if *from != ComplianceStatus::Unknown {
                if *from == ComplianceStatus::Revoked {
                    client.set_compliance_status(&admin, &subject, &ComplianceStatus::Approved);
                }
                client.set_compliance_status(&admin, &subject, from);
            }
            assert_eq!(client.get_compliance_status(&subject), *from);

            let r = client.try_set_compliance_status(&admin, &subject, to);
            let expected = if from == to {
                Error::ComplianceStatusUnchanged
            } else {
                Error::InvalidComplianceTransition
            };
            assert_eq!(r, Err(Ok(expected)), "transition should have been rejected");
            // Rejected transitions must never mutate state.
            assert_eq!(client.get_compliance_status(&subject), *from);
        }
    }
}

#[test]
fn test_no_op_transition_reports_unchanged() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Approved);
    let r = client.try_set_compliance_status(&admin, &user1, &ComplianceStatus::Approved);
    assert_eq!(r, Err(Ok(Error::ComplianceStatusUnchanged)));
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Approved
    );
}

// ─── Lifecycle authorization ─────────────────────────────────────────────────

#[test]
fn test_compliance_officer_can_drive_the_lifecycle() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::ComplianceOfficer);

    client.set_compliance_status(&user1, &user2, &ComplianceStatus::Pending);
    client.set_compliance_status(&user1, &user2, &ComplianceStatus::Approved);
    assert_eq!(
        client.get_compliance_status(&user2),
        ComplianceStatus::Approved
    );

    // A compliance officer may also impose a freeze...
    client.set_compliance_status(&user1, &user2, &ComplianceStatus::Blocked);
    assert_eq!(
        client.get_compliance_status(&user2),
        ComplianceStatus::Blocked
    );
}

#[test]
fn test_emergency_officer_can_drive_the_lifecycle() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::EmergencyOfficer);

    client.set_compliance_status(&user1, &user2, &ComplianceStatus::Blocked);
    assert_eq!(
        client.get_compliance_status(&user2),
        ComplianceStatus::Blocked
    );
}

#[test]
fn test_only_admin_can_unblock() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::ComplianceOfficer);

    client.set_compliance_status(&user1, &user2, &ComplianceStatus::Blocked);

    // ...but must not be able to lift one. Mirrors the pause/unpause
    // asymmetry: a compromised officer cannot release a sanctioned address.
    let r = client.try_set_compliance_status(&user1, &user2, &ComplianceStatus::Pending);
    assert_eq!(r, Err(Ok(Error::Unauthorized)));
    assert_eq!(
        client.get_compliance_status(&user2),
        ComplianceStatus::Blocked
    );

    // The supreme admin can.
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Pending);
    assert_eq!(
        client.get_compliance_status(&user2),
        ComplianceStatus::Pending
    );
}

#[test]
fn test_emergency_officer_cannot_unblock() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::EmergencyOfficer);
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Blocked);

    let r = client.try_set_compliance_status(&user1, &user2, &ComplianceStatus::Pending);
    assert_eq!(r, Err(Ok(Error::Unauthorized)));
}

#[test]
fn test_unauthorized_caller_cannot_change_compliance_status() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::AssetManager);

    // AssetManager is not a compliance role.
    let r = client.try_set_compliance_status(&user1, &user2, &ComplianceStatus::Approved);
    assert_eq!(r, Err(Ok(Error::Unauthorized)));

    // No role at all.
    let stranger = Address::generate(&env);
    let r = client.try_set_compliance_status(&stranger, &user2, &ComplianceStatus::Approved);
    assert_eq!(r, Err(Ok(Error::Unauthorized)));

    assert_eq!(
        client.get_compliance_status(&user2),
        ComplianceStatus::Unknown
    );
}

#[test]
fn test_set_compliance_status_blocked_when_paused() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.pause(&admin);

    let r = client.try_set_compliance_status(&admin, &user1, &ComplianceStatus::Approved);
    assert_eq!(r, Err(Ok(Error::ContractPaused)));
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Unknown
    );
}

// ─── Lifecycle enforcement on minting and transfers ──────────────────────────

#[test]
fn test_mint_rejects_each_non_approved_status_with_its_own_code() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);

    // Unknown
    let unknown = Address::generate(&env);
    let r = client.try_mint_asset(&user1, &unknown, &100);
    assert_eq!(r, Err(Ok(Error::ReceiverNotWhitelisted)));

    // Pending — KYC in flight must fail closed.
    let pending = Address::generate(&env);
    client.set_compliance_status(&admin, &pending, &ComplianceStatus::Pending);
    let r = client.try_mint_asset(&user1, &pending, &100);
    assert_eq!(r, Err(Ok(Error::ReceiverCompliancePending)));

    // Revoked
    let revoked = Address::generate(&env);
    client.set_compliance_status(&admin, &revoked, &ComplianceStatus::Approved);
    client.set_compliance_status(&admin, &revoked, &ComplianceStatus::Revoked);
    let r = client.try_mint_asset(&user1, &revoked, &100);
    assert_eq!(r, Err(Ok(Error::ReceiverNotWhitelisted)));

    // Blocked — a distinct code so a client never invites a re-submission.
    let blocked = Address::generate(&env);
    client.set_compliance_status(&admin, &blocked, &ComplianceStatus::Blocked);
    let r = client.try_mint_asset(&user1, &blocked, &100);
    assert_eq!(r, Err(Ok(Error::ReceiverBlocked)));

    // Approved is the only state that mints.
    let approved = Address::generate(&env);
    client.set_compliance_status(&admin, &approved, &ComplianceStatus::Approved);
    client.mint_asset(&user1, &approved, &100);
    assert_eq!(client.get_balance_of(&approved), 100);
    assert_eq!(client.get_total_supply(), 100);
}

#[test]
fn test_transfer_rejects_each_non_approved_sender_status() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Approved);
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Approved);
    client.mint_asset(&user1, &user1, &1000);

    // Approved → Pending: the holder keeps their balance but is frozen out.
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Pending);
    let r = client.try_transfer(&user1, &user2, &100);
    assert_eq!(r, Err(Ok(Error::SenderCompliancePending)));
    assert_eq!(client.get_balance_of(&user1), 1000);

    // Pending → Revoked
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Revoked);
    let r = client.try_transfer(&user1, &user2, &100);
    assert_eq!(r, Err(Ok(Error::SenderNotWhitelisted)));

    // Revoked → Blocked
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Blocked);
    let r = client.try_transfer(&user1, &user2, &100);
    assert_eq!(r, Err(Ok(Error::SenderBlocked)));

    // Balance survived every rejected attempt.
    assert_eq!(client.get_balance_of(&user1), 1000);
    assert_eq!(client.get_balance_of(&user2), 0);
}

#[test]
fn test_transfer_rejects_each_non_approved_receiver_status() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Approved);
    client.mint_asset(&user1, &user1, &1000);

    // Unknown receiver
    let r = client.try_transfer(&user1, &user2, &100);
    assert_eq!(r, Err(Ok(Error::ReceiverNotWhitelisted)));

    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Pending);
    let r = client.try_transfer(&user1, &user2, &100);
    assert_eq!(r, Err(Ok(Error::ReceiverCompliancePending)));

    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Blocked);
    let r = client.try_transfer(&user1, &user2, &100);
    assert_eq!(r, Err(Ok(Error::ReceiverBlocked)));

    // Unblock through review, then clear: the transfer now succeeds.
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Pending);
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Approved);
    client.transfer(&user1, &user2, &100);
    assert_eq!(client.get_balance_of(&user2), 100);
}

#[test]
fn test_sender_status_is_reported_before_receiver_status() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Blocked);
    // user2 is Unknown — both parties are ineligible.

    let r = client.try_transfer(&user1, &user2, &100);
    assert_eq!(r, Err(Ok(Error::SenderBlocked)));
}

#[test]
fn test_blocking_a_holder_freezes_their_balance_without_destroying_it() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Approved);
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Approved);
    client.mint_asset(&user1, &user1, &500);

    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Blocked);

    assert_eq!(client.get_balance_of(&user1), 500);
    assert!(client.try_transfer(&user1, &user2, &1).is_err());
    // ...and nobody can top them up either.
    assert!(client.try_mint_asset(&user1, &user1, &1).is_err());
    assert_eq!(client.get_balance_of(&user1), 500);
    assert_eq!(client.get_total_supply(), 500);
}

// ─── Lifecycle events ────────────────────────────────────────────────────────

#[test]
fn test_set_compliance_status_emits_lifecycle_event() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Pending);
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Approved);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("compliance_status_changed",).into_val(&env),
                ComplianceStatusChangedEvent {
                    caller: admin,
                    user: user1,
                    previous_status: ComplianceStatus::Pending,
                    new_status: ComplianceStatus::Approved,
                }
                .into_val(&env),
            ),
        ]
    );
}

#[test]
fn test_rejected_transition_emits_no_event() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Blocked);

    let r = client.try_set_compliance_status(&admin, &user1, &ComplianceStatus::Approved);
    assert_eq!(r, Err(Ok(Error::InvalidComplianceTransition)));
    // Soroban discards events from a reverted invocation.
    assert_eq!(env.events().all().events().len(), 0);
}

#[test]
fn test_idempotent_whitelist_emits_no_duplicate_lifecycle_event() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    client.whitelist_user(&admin, &user1);
    // Second call is a no-op transition: only the legacy event is emitted.
    client.whitelist_user(&admin, &user1);

    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("user_whitelisted",).into_val(&env),
                UserWhitelistedEvent {
                    caller: admin,
                    user: user1,
                }
                .into_val(&env),
            ),
        ]
    );
}

// ─── Legacy whitelist wrappers vs. the lifecycle ─────────────────────────────

#[test]
fn test_legacy_whitelist_wrappers_drive_the_lifecycle() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    client.whitelist_user(&admin, &user1);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Approved
    );
    assert!(client.is_whitelisted(&user1));

    client.revoke_whitelist(&admin, &user1);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Revoked
    );
    assert!(!client.is_whitelisted(&user1));

    // Re-approval through the legacy path works from `Revoked`.
    client.whitelist_user(&admin, &user1);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Approved
    );
}

#[test]
fn test_legacy_whitelist_cannot_lift_a_block() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Blocked);

    let r = client.try_whitelist_user(&admin, &user1);
    assert_eq!(r, Err(Ok(Error::InvalidComplianceTransition)));
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Blocked
    );
    assert!(!client.is_whitelisted(&user1));
}

#[test]
fn test_legacy_revoke_does_not_downgrade_a_block() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Blocked);

    // Tolerated as a no-op on the lifecycle — the stronger state survives.
    client.revoke_whitelist(&admin, &user1);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Blocked
    );
}

#[test]
fn test_legacy_revoke_of_unknown_address_is_a_tolerated_no_op() {
    let (env, client, admin, user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    client.revoke_whitelist(&admin, &user1);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Unknown
    );
}

// ─── Lifecycle in the eligibility read helpers ───────────────────────────────

#[test]
fn test_eligibility_snapshot_exposes_lifecycle_status() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);

    let e = client.get_investor_eligibility(&user2);
    assert_eq!(e.compliance_status, ComplianceStatus::Unknown);
    assert!(!e.whitelisted);
    assert!(!e.can_receive);
    assert!(!e.can_send);

    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Pending);
    let e = client.get_investor_eligibility(&user2);
    assert_eq!(e.compliance_status, ComplianceStatus::Pending);
    assert!(!e.whitelisted);
    assert!(!e.can_receive);

    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Approved);
    client.mint_asset(&user1, &user2, &250);
    let e = client.get_investor_eligibility(&user2);
    assert_eq!(e.compliance_status, ComplianceStatus::Approved);
    assert!(e.whitelisted);
    assert!(e.can_receive);
    assert!(e.can_send);
    assert_eq!(e.balance, 250);

    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Blocked);
    let e = client.get_investor_eligibility(&user2);
    assert_eq!(e.compliance_status, ComplianceStatus::Blocked);
    assert!(!e.can_receive);
    assert!(!e.can_send);
    // Balance is frozen, not erased.
    assert_eq!(e.balance, 250);
}

#[test]
fn test_check_transfer_eligibility_tracks_lifecycle_changes() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Approved);
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Approved);
    client.mint_asset(&user1, &user1, &1000);

    assert!(client.check_transfer_eligibility(&user1, &user2, &100));

    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Pending);
    assert!(!client.check_transfer_eligibility(&user1, &user2, &100));

    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Approved);
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Blocked);
    assert!(!client.check_transfer_eligibility(&user1, &user2, &100));
}

// ─── Lifecycle capability advertisement ──────────────────────────────────────

#[test]
fn test_capabilities_advertise_the_compliance_lifecycle() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    let caps = client.get_capabilities();
    assert_eq!(
        caps.compliance.lifecycle_states,
        CapabilityStatus::Supported
    );
    assert_eq!(
        caps.compliance.lifecycle_transitions,
        CapabilityStatus::Supported
    );
    assert_eq!(
        caps.compliance.batch_whitelisting,
        CapabilityStatus::Supported
    );
    assert_eq!(
        caps.compliance.batch_status_updates,
        CapabilityStatus::Supported
    );
    assert_eq!(
        caps.events.compliance_lifecycle_events,
        CapabilityStatus::Supported
    );

    assert_eq!(
        client.supports_capability(&Symbol::new(&env, "compliance_lifecycle")),
        CapabilityStatus::Supported
    );
    assert_eq!(
        client.supports_capability(&Symbol::new(&env, "compliance_transitions")),
        CapabilityStatus::Supported
    );
    assert_eq!(
        client.supports_capability(&Symbol::new(&env, "batch_whitelisting")),
        CapabilityStatus::Supported
    );
    assert_eq!(
        client.supports_capability(&Symbol::new(&env, "compliance_batch_updates")),
        CapabilityStatus::Supported
    );
    assert_eq!(
        client.supports_capability(&Symbol::new(&env, "compliance_lifecycle_events")),
        CapabilityStatus::Supported
    );

    // The new keys are advertised in the registry.
    let keys = client.get_capability_keys();
    assert!(keys.contains(Symbol::new(&env, "compliance_lifecycle")));
    assert!(keys.contains(Symbol::new(&env, "compliance_transitions")));
    assert!(keys.contains(Symbol::new(&env, "compliance_batch_updates")));
    assert!(keys.contains(Symbol::new(&env, "compliance_lifecycle_events")));
}

// ─── Public interface compatibility checks (#37) ─────────────────────────────

#[test]
fn test_interface_compatibility_matching_schema_and_supported_keys_is_compatible() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    let required = vec![
        &env,
        Symbol::new(&env, "whitelist"),
        Symbol::new(&env, "transfers"),
    ];
    let report = client.check_interface_compatibility(&CAPABILITY_SCHEMA_VERSION, &required);

    assert_eq!(report.contract_schema_version, CAPABILITY_SCHEMA_VERSION);
    assert_eq!(report.client_schema_version, CAPABILITY_SCHEMA_VERSION);
    assert_eq!(report.schema_relation, SchemaVersionRelation::Matching);
    assert_eq!(report.unsupported_required.len(), 0);
    assert!(report.compatible);
}

#[test]
fn test_interface_compatibility_older_client_schema_is_still_compatible() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    // A client built against an earlier schema is forward-compatible as long
    // as everything it actually asks for is still Supported.
    let required = vec![&env, Symbol::new(&env, "whitelist")];
    let report = client.check_interface_compatibility(&1u32, &required);

    assert_eq!(report.schema_relation, SchemaVersionRelation::ClientOlder);
    assert!(report.compatible);
}

#[test]
fn test_interface_compatibility_newer_client_schema_flags_gap_when_relevant() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    // A client from a future schema version claiming a key this deployment
    // never heard of must be reported, not silently treated as fine.
    let required = vec![&env, Symbol::new(&env, "some_future_capability")];
    let newer_version = CAPABILITY_SCHEMA_VERSION + 1;
    let report = client.check_interface_compatibility(&newer_version, &required);

    assert_eq!(report.schema_relation, SchemaVersionRelation::ClientNewer);
    assert_eq!(report.unsupported_required.len(), 1);
    assert!(report
        .unsupported_required
        .contains(Symbol::new(&env, "some_future_capability")));
    assert!(!report.compatible);
}

#[test]
fn test_interface_compatibility_reports_every_unsupported_required_key() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    // `burning` is a real, permanently Unsupported key (no burn entrypoint).
    // `allowances` is Planned, which also does not count as Supported.
    let required = vec![
        &env,
        Symbol::new(&env, "whitelist"),
        Symbol::new(&env, "burning"),
        Symbol::new(&env, "allowances"),
    ];
    let report = client.check_interface_compatibility(&CAPABILITY_SCHEMA_VERSION, &required);

    assert_eq!(report.unsupported_required.len(), 2);
    assert!(report
        .unsupported_required
        .contains(Symbol::new(&env, "burning")));
    assert!(report
        .unsupported_required
        .contains(Symbol::new(&env, "allowances")));
    assert!(!report.compatible);
}

#[test]
fn test_interface_compatibility_empty_requirements_always_compatible() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    // No requirements means nothing to fail on, regardless of schema drift.
    let required = vec![&env];
    let newer_version = CAPABILITY_SCHEMA_VERSION + 5;
    let report = client.check_interface_compatibility(&newer_version, &required);

    assert!(report.unsupported_required.is_empty());
    assert!(report.compatible);
}

#[test]
fn test_interface_compatibility_agrees_with_supports_capability() {
    let (env, client, admin, _user1, _user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    // Cross-check against the independent single-key resolver so the two
    // entrypoints can never silently disagree.
    let key = Symbol::new(&env, "decimals"); // Planned, not Supported.
    let required = vec![&env, key.clone()];
    let report = client.check_interface_compatibility(&CAPABILITY_SCHEMA_VERSION, &required);

    let direct_status = client.supports_capability(&key);
    assert_ne!(direct_status, CapabilityStatus::Supported);
    assert!(report.unsupported_required.contains(key));
}

#[test]
fn test_interface_compatibility_never_mutates_and_works_before_initialize() {
    let (env, client, _admin, _user1, _user2) = setup();

    // No auth mocked and no initialize() call — must still answer safely.
    let required = vec![&env, Symbol::new(&env, "whitelist")];
    let report = client.check_interface_compatibility(&CAPABILITY_SCHEMA_VERSION, &required);
    assert!(report.compatible);

    // Re-running it changes nothing about contract state.
    let total_supply_before = client.get_total_supply();
    let _ = client.check_interface_compatibility(&CAPABILITY_SCHEMA_VERSION, &required);
    assert_eq!(client.get_total_supply(), total_supply_before);
}

#[test]
fn test_lifecycle_reads_never_revert_and_never_mutate() {
    let (env, client, _admin, user1, _user2) = setup();

    // Before initialize, with no auth mocked, none of these may panic.
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Unknown
    );
    assert!(client
        .is_compliance_transition_allowed(&ComplianceStatus::Unknown, &ComplianceStatus::Approved));
    assert_eq!(client.get_allowed_transitions_for(&user1).len(), 3);
    assert_eq!(
        client
            .get_allowed_transitions(&ComplianceStatus::Blocked)
            .len(),
        1
    );

    // Pure reads publish nothing.
    assert_eq!(env.events().all().events().len(), 0);
    assert_eq!(
        client.get_compliance_status(&user1),
        ComplianceStatus::Unknown
    );
}

#[test]
fn test_compliance_status_lifecycle_invariants() {
    // A full state-machine walk: Unknown → Pending → Approved → Revoked →
    // Re-approved, asserting the transition invariants that prevent compliance
    // bypass and lockout bugs at every hop.
    let fixture = ComplianceFixture::new();
    let investor = fixture.target.clone();
    let recipient = Address::generate(&fixture.env);

    // ── Unknown ───────────────────────────────────────────────────────────
    // Never targeted: off the whitelist, and assets cannot be minted to it.
    assert_eq!(
        fixture.is_target_approved(),
        ComplianceStatus::Unknown.is_approved()
    );
    let result = fixture
        .client
        .try_mint_asset(&fixture.manager, &investor, &100);
    assert_eq!(result, Err(Ok(Error::ReceiverNotWhitelisted)));

    // ── Pending ───────────────────────────────────────────────────────────
    // A rejected approval attempt (unauthorised caller) leaves the address
    // off the whitelist — it is pending, and minting stays blocked.
    let outcome = fixture.attempt(ComplianceAction::Approve, TransitionCaller::NoRole);
    assert_eq!(outcome, TransitionOutcome::Rejected(Error::Unauthorized));
    assert!(!fixture.is_target_approved());
    let result = fixture
        .client
        .try_mint_asset(&fixture.manager, &investor, &100);
    assert_eq!(result, Err(Ok(Error::ReceiverNotWhitelisted)));

    // A blocked approval attempt while paused also leaves it pending.
    fixture.client.pause(&fixture.admin);
    let outcome = fixture.attempt(
        ComplianceAction::Approve,
        TransitionCaller::ComplianceOfficer,
    );
    assert_eq!(outcome, TransitionOutcome::Rejected(Error::ContractPaused));
    assert!(!fixture.is_target_approved());
    fixture.client.unpause(&fixture.admin);

    // ── Approved ──────────────────────────────────────────────────────────
    // A committed approval flips the status and unlocks receiving.
    fixture.client.whitelist_user(&fixture.officer, &investor);
    assert!(fixture.is_target_approved());
    fixture.client.mint_asset(&fixture.manager, &investor, &100);
    assert_eq!(fixture.client.get_balance_of(&investor), 100);

    // ── Revoked ───────────────────────────────────────────────────────────
    // Revocation locks sending AND receiving for the investor...
    fixture.client.revoke_whitelist(&fixture.officer, &investor);
    assert!(!fixture.is_target_approved());
    fixture.client.whitelist_user(&fixture.officer, &recipient);

    let result = fixture
        .client
        .try_mint_asset(&fixture.manager, &investor, &50);
    assert_eq!(result, Err(Ok(Error::ReceiverNotWhitelisted)));
    let result = fixture.client.try_transfer(&investor, &recipient, &50);
    assert_eq!(result, Err(Ok(Error::SenderNotWhitelisted)));
    // ...while the balance itself is preserved, not destroyed.
    assert_eq!(fixture.client.get_balance_of(&investor), 100);

    // ── Re-approved ───────────────────────────────────────────────────────
    // Revocation is not a permanent lockout: an authorised caller can
    // re-approve, restoring full movement rights.
    fixture.client.whitelist_user(&fixture.emergency, &investor);
    assert!(fixture.is_target_approved());
    fixture.client.transfer(&investor, &recipient, &40);

    assert_eq!(fixture.client.get_balance_of(&investor), 60);
    assert_eq!(fixture.client.get_balance_of(&recipient), 40);
    assert_eq!(fixture.client.get_total_supply(), 100);
}

#[test]
fn test_compliance_transitions_rejected_after_officer_role_revoked() {
    // Wrong-caller nuance: the moment the admin strips a compliance officer's
    // role, that officer's transitions become invalid — rejected, state
    // unchanged, no event — even for addresses they personally approved.
    let fixture = ComplianceFixture::new();
    fixture
        .client
        .whitelist_user(&fixture.officer, &fixture.target);
    assert!(fixture.is_target_approved());
    let outsider = Address::generate(&fixture.env);

    fixture.client.remove_role(&fixture.admin, &fixture.officer);

    let outcome = fixture.attempt(
        ComplianceAction::Revoke,
        TransitionCaller::ComplianceOfficer,
    );
    assert_eq!(outcome, TransitionOutcome::Rejected(Error::Unauthorized));
    assert!(fixture.is_target_approved());
    assert_eq!(fixture.last_invocation_event_count(), 0);

    let result = fixture
        .client
        .try_whitelist_user(&fixture.officer, &outsider);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));
    assert!(!fixture.client.is_whitelisted(&outsider));

    // The admin can still act — removing one officer never wedges the registry.
    fixture
        .client
        .revoke_whitelist(&fixture.admin, &fixture.target);
    assert!(!fixture.is_target_approved());
}

// ─── Compliant minting invariants (#8) ─────────────────────────────────────
//
// A deterministic scenario matrix proving mint_asset only succeeds for a
// compliant recipient, an authorised issuer, and a movable (Active) asset —
// and that every rejected attempt, including a repeated one, leaves balance
// and total supply exactly as they were before the call.

#[test]
fn test_compliant_mint_succeeds_and_updates_balance_and_supply() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Approved);

    let r = client.try_mint_asset(&user1, &user2, &250);
    assert!(r.is_ok());
    assert_eq!(client.get_balance_of(&user2), 250);
    assert_eq!(client.get_total_supply(), 250);
}

#[test]
fn test_mint_rejects_non_whitelisted_recipient_and_leaves_state_unchanged() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    // user2 is never whitelisted — default compliance status is Unknown.

    let r = client.try_mint_asset(&user1, &user2, &100);
    assert_eq!(r, Err(Ok(Error::ReceiverNotWhitelisted)));
    assert_eq!(client.get_balance_of(&user2), 0);
    assert_eq!(client.get_total_supply(), 0);
}

#[test]
fn test_mint_rejects_unauthorised_issuer_and_leaves_state_unchanged() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Approved);
    // user1 is never granted AssetManager (or Admin) — an unauthorised issuer.

    let r = client.try_mint_asset(&user1, &user2, &100);
    assert_eq!(r, Err(Ok(Error::Unauthorized)));
    assert_eq!(client.get_balance_of(&user2), 0);
    assert_eq!(client.get_total_supply(), 0);
}

#[test]
fn test_mint_rejects_invalid_asset_state_and_leaves_state_unchanged() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_role(&admin, &user1, &Role::AssetManager);
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Approved);
    // Asset status is left at its default (Draft) — never activated, so it
    // is not yet a valid mint target.

    let r = client.try_mint_asset(&user1, &user2, &100);
    assert_eq!(r, Err(Ok(Error::AssetBlockedRestriction)));
    assert_eq!(client.get_balance_of(&user2), 0);
    assert_eq!(client.get_total_supply(), 0);

    // Also invalid once the asset is explicitly retired — a terminal state.
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_asset_status(&admin, &AssetStatus::Retired);
    let r = client.try_mint_asset(&user1, &user2, &100);
    assert_eq!(r, Err(Ok(Error::AssetRetiredRestriction)));
    assert_eq!(client.get_balance_of(&user2), 0);
    assert_eq!(client.get_total_supply(), 0);
}

#[test]
fn test_mint_rejects_revoked_compliance_and_leaves_state_unchanged() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);

    // user2 was compliant once, then had their approval revoked.
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Approved);
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Revoked);

    let r = client.try_mint_asset(&user1, &user2, &100);
    assert_eq!(r, Err(Ok(Error::ReceiverNotWhitelisted)));
    assert_eq!(client.get_balance_of(&user2), 0);
    assert_eq!(client.get_total_supply(), 0);
}

#[test]
fn test_repeated_rejected_mint_attempts_never_mutate_state() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.set_role(&admin, &user1, &Role::AssetManager);
    // user2 stays non-compliant for every attempt below.

    for _ in 0..5 {
        let r = client.try_mint_asset(&user1, &user2, &100);
        assert_eq!(r, Err(Ok(Error::ReceiverNotWhitelisted)));
        assert_eq!(client.get_balance_of(&user2), 0);
        assert_eq!(client.get_total_supply(), 0);
    }

    // The repeated rejections left the recipient just as mintable as before
    // — no latent state (e.g. a partially-consumed cap) survived the retries.
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Approved);
    client.mint_asset(&user1, &user2, &100);
    assert_eq!(client.get_balance_of(&user2), 100);
    assert_eq!(client.get_total_supply(), 100);
}

// ─── COMPLIANCE STATUS TRANSITION GUARDS ──────────────────────────────────────
//
// The guard module (src/compliance_guards.rs) is the single evaluation shared
// by the pre-flight read entrypoints and by every state-changing compliance
// call. The invariant these tests exist to protect is therefore not "the guard
// returns the right answer" in isolation, but that the guard's answer and the
// contract's actual behaviour can never disagree — that is what makes it safe
// for a dashboard to disable an action, or an SDK to skip a simulation, on the
// strength of a read. The model is documented in
// docs/compliance-transition-guards.md.

/// Drives `user` into `target` on a freshly initialized contract, using the
/// admin so the seeding itself can never be refused by a role check.
///
/// Only legal edges are used, so seeding exercises the same matrix under test
/// instead of writing storage behind its back.
fn seed_status(
    client: &AegisContractClient<'static>,
    admin: &Address,
    user: &Address,
    target: ComplianceStatus,
) {
    match target {
        ComplianceStatus::Unknown => {}
        ComplianceStatus::Pending => {
            client.set_compliance_status(admin, user, &ComplianceStatus::Pending);
        }
        ComplianceStatus::Approved => {
            client.set_compliance_status(admin, user, &ComplianceStatus::Approved);
        }
        ComplianceStatus::Revoked => {
            client.set_compliance_status(admin, user, &ComplianceStatus::Pending);
            client.set_compliance_status(admin, user, &ComplianceStatus::Revoked);
        }
        ComplianceStatus::Blocked => {
            client.set_compliance_status(admin, user, &ComplianceStatus::Blocked);
        }
    }
    assert_eq!(client.get_compliance_status(user), target, "seeding failed");
}

/// A fresh deployment with an admin, a ComplianceOfficer, and an investor.
fn setup_guard_world() -> (Env, AegisContractClient<'static>, Address, Address, Address) {
    let (env, client, admin, officer, investor) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_role(&admin, &officer, &Role::ComplianceOfficer);
    (env, client, admin, officer, investor)
}

/// Asserts that a pre-flight verdict and a real submission agree, and returns
/// nothing — the assertion *is* the point.
fn assert_guard_matches_execution(
    client: &AegisContractClient<'static>,
    caller: &Address,
    user: &Address,
    target: ComplianceStatus,
) {
    let check = client.check_compliance_transition(caller, user, &target);
    let before = client.get_compliance_status(user);
    let result = client.try_set_compliance_status(caller, user, &target);

    match result {
        Ok(_) => {
            assert!(
                check.allowed,
                "guard rejected ({:?} -> {:?}) with {:?} but the call succeeded",
                before, target, check.reason
            );
            assert_eq!(check.error_code, None);
            assert_eq!(
                client.get_compliance_status(user),
                target,
                "committed transition did not reach the requested status"
            );
        }
        Err(Ok(err)) => {
            assert!(
                !check.allowed,
                "guard allowed ({:?} -> {:?}) but the call reverted with {:?}",
                before, target, err
            );
            assert_eq!(
                check.error_code,
                Some(err as u32),
                "guard predicted a different error code for ({:?} -> {:?})",
                before,
                target
            );
            assert_eq!(
                client.get_compliance_status(user),
                before,
                "a rejected transition changed the stored status"
            );
        }
        Err(Err(err)) => panic!("unexpected host error: {err:?}"),
    }
}

#[test]
fn test_guard_matches_enforcement_for_every_edge_as_officer() {
    // 5 source statuses x 5 targets = the complete edge space, each on its own
    // deployment so the result depends only on the pair under test.
    for from in ALL_STATUSES {
        for to in ALL_STATUSES {
            let (_env, client, admin, officer, investor) = setup_guard_world();
            seed_status(&client, &admin, &investor, from);
            assert_guard_matches_execution(&client, &officer, &investor, to);
        }
    }
}

#[test]
fn test_guard_matches_enforcement_for_every_edge_as_admin() {
    // The admin bypasses role checks, so this pass covers the edges an officer
    // can never reach — in particular the admin-only exit from `Blocked`.
    for from in ALL_STATUSES {
        for to in ALL_STATUSES {
            let (_env, client, admin, _officer, investor) = setup_guard_world();
            seed_status(&client, &admin, &investor, from);
            assert_guard_matches_execution(&client, &admin, &investor, to);
        }
    }
}

#[test]
fn test_guard_matches_enforcement_for_every_edge_as_unauthorized_caller() {
    // A caller with a wrong-scoped role must be refused on every edge, and the
    // guard must say so in advance rather than letting a client discover it
    // from a revert.
    for from in ALL_STATUSES {
        for to in ALL_STATUSES {
            let (_env, client, admin, _officer, investor) = setup_guard_world();
            let outsider = Address::generate(&_env);
            client.set_role(&admin, &outsider, &Role::AssetManager);
            seed_status(&client, &admin, &investor, from);

            let check = client.check_compliance_transition(&outsider, &investor, &to);
            assert!(!check.allowed);
            assert!(check.reason.is_authorization_failure());
            assert_guard_matches_execution(&client, &outsider, &investor, to);
        }
    }
}

#[test]
fn test_guard_reports_blocked_requires_admin_not_generic_unauthorized() {
    let (_env, client, admin, officer, investor) = setup_guard_world();
    seed_status(&client, &admin, &investor, ComplianceStatus::Blocked);

    // The officer holds a valid compliance role, so "you lack a role" would be
    // the wrong explanation: the refusal is specific to leaving `Blocked`.
    let check = client.check_compliance_transition(&officer, &investor, &ComplianceStatus::Pending);
    assert!(!check.allowed);
    assert_eq!(check.reason, TransitionGuard::BlockedRequiresAdmin);
    assert_eq!(check.error_code, Some(Error::Unauthorized as u32));

    // A caller with no role at all gets the same refusal for a blocked
    // address — the block, not the missing role, is the binding constraint.
    let nobody = Address::generate(&_env);
    let nobody_check =
        client.check_compliance_transition(&nobody, &investor, &ComplianceStatus::Pending);
    assert_eq!(nobody_check.reason, TransitionGuard::BlockedRequiresAdmin);

    // Only the admin may lift it, and only into re-review.
    let admin_check =
        client.check_compliance_transition(&admin, &investor, &ComplianceStatus::Pending);
    assert!(admin_check.allowed);
    let admin_direct =
        client.check_compliance_transition(&admin, &investor, &ComplianceStatus::Approved);
    assert!(!admin_direct.allowed);
    assert_eq!(admin_direct.reason, TransitionGuard::TransitionForbidden);
}

#[test]
fn test_guard_reports_status_unchanged_for_every_self_edge() {
    for status in ALL_STATUSES {
        let (_env, client, admin, _officer, investor) = setup_guard_world();
        seed_status(&client, &admin, &investor, status);

        let check = client.check_compliance_transition(&admin, &investor, &status);
        assert!(!check.allowed);
        // `Blocked -> Blocked` is refused for authority before it is ever
        // compared, because only the admin may act on a blocked address; the
        // admin used here reaches the no-op rule itself.
        assert_eq!(check.reason, TransitionGuard::StatusUnchanged);
        assert_eq!(
            check.error_code,
            Some(Error::ComplianceStatusUnchanged as u32)
        );
    }
}

#[test]
fn test_guard_reports_target_unknown_as_its_own_reason() {
    // `Unknown` is unreachable from every source, including itself. It gets a
    // dedicated reason so a client can drop it from the target list entirely
    // instead of showing an edge that can never be offered.
    for from in ALL_STATUSES {
        let (_env, client, admin, _officer, investor) = setup_guard_world();
        seed_status(&client, &admin, &investor, from);

        let check =
            client.check_compliance_transition(&admin, &investor, &ComplianceStatus::Unknown);
        assert!(!check.allowed);
        let expected = if from == ComplianceStatus::Unknown {
            // The no-op rule is evaluated first, so an already-unknown address
            // reports the more specific "nothing would change".
            TransitionGuard::StatusUnchanged
        } else {
            TransitionGuard::TargetUnknownForbidden
        };
        assert_eq!(check.reason, expected, "from {from:?}");
    }
}

#[test]
fn test_guard_reports_pause_ahead_of_authority() {
    let (_env, client, admin, officer, investor) = setup_guard_world();
    seed_status(&client, &admin, &investor, ComplianceStatus::Pending);
    client.pause(&admin);

    // The pause is reported first for every caller class, so a paused contract
    // never leaks whether a caller would otherwise have qualified.
    let outsider = Address::generate(&_env);
    for caller in [&admin, &officer, &outsider] {
        let check =
            client.check_compliance_transition(caller, &investor, &ComplianceStatus::Approved);
        assert!(!check.allowed);
        assert_eq!(check.reason, TransitionGuard::ContractPaused);
        assert_eq!(check.error_code, Some(Error::ContractPaused as u32));
    }

    // The read itself stays available while paused — a dashboard can still
    // explain why every control is disabled.
    assert_eq!(
        client.get_compliance_status(&investor),
        ComplianceStatus::Pending
    );

    // And the pause is not a lockout: the same edge clears once unpaused.
    client.unpause(&admin);
    let after =
        client.check_compliance_transition(&officer, &investor, &ComplianceStatus::Approved);
    assert!(after.allowed);
    assert_eq!(after.reason, TransitionGuard::Allowed);
}

#[test]
fn test_guard_reports_not_initialized_instead_of_panicking() {
    // Before `initialize` there is no admin to check a caller against. The
    // guard must still answer — a view entrypoint that panics is unusable for
    // a dashboard rendering a not-yet-configured deployment.
    let (env, client, admin, _user1, investor) = setup();
    env.mock_all_auths();

    let check = client.check_compliance_transition(&admin, &investor, &ComplianceStatus::Approved);
    assert!(!check.allowed);
    assert_eq!(check.reason, TransitionGuard::NotInitialized);
    assert_eq!(check.error_code, Some(Error::NotInitialized as u32));

    // The prediction holds: submitting really does fail with that code.
    let result = client.try_set_compliance_status(&admin, &investor, &ComplianceStatus::Approved);
    assert_eq!(result, Err(Ok(Error::NotInitialized)));
}

#[test]
fn test_guard_report_carries_a_consistent_status_snapshot() {
    let (_env, client, admin, officer, investor) = setup_guard_world();
    seed_status(&client, &admin, &investor, ComplianceStatus::Approved);

    let check = client.check_compliance_transition(&officer, &investor, &ComplianceStatus::Revoked);
    assert_eq!(check.user, investor);
    assert_eq!(check.caller, officer);
    assert_eq!(check.current_status, ComplianceStatus::Approved);
    assert_eq!(check.requested_status, ComplianceStatus::Revoked);
    assert!(check.allowed);
    assert_eq!(check.reason, TransitionGuard::Allowed);
    assert_eq!(check.error_code, None);
}

#[test]
fn test_guard_reads_never_mutate_state() {
    let (env, client, admin, officer, investor) = setup_guard_world();
    seed_status(&client, &admin, &investor, ComplianceStatus::Approved);
    let events_before = env.events().all();

    for to in ALL_STATUSES {
        client.check_compliance_transition(&officer, &investor, &to);
        client.get_compliance_transition_guard(&officer, &investor, &to);
    }

    assert_eq!(
        client.get_compliance_status(&investor),
        ComplianceStatus::Approved
    );
    assert!(client.is_whitelisted(&investor));
    assert_eq!(client.get_role_of(&officer), Role::ComplianceOfficer);
    assert!(!client.is_paused());
    // A pre-flight read is not a compliance action and must leave no trace in
    // the audit stream.
    assert_eq!(env.events().all(), events_before);
}

#[test]
fn test_guard_verdict_tracks_role_revocation() {
    let (_env, client, admin, officer, investor) = setup_guard_world();

    let before =
        client.check_compliance_transition(&officer, &investor, &ComplianceStatus::Approved);
    assert!(before.allowed);

    client.remove_role(&admin, &officer);

    // Authority is evaluated at call time, never cached, so the verdict flips
    // immediately — including for an address this officer had approved before.
    let after =
        client.check_compliance_transition(&officer, &investor, &ComplianceStatus::Approved);
    assert!(!after.allowed);
    assert_eq!(after.reason, TransitionGuard::CallerUnauthorized);
    assert_guard_matches_execution(&client, &officer, &investor, ComplianceStatus::Approved);
}

#[test]
fn test_guard_accepts_emergency_officer_and_rejects_asset_manager() {
    let (_env, client, admin, _officer, investor) = setup_guard_world();
    let emergency = Address::generate(&_env);
    let manager = Address::generate(&_env);
    client.set_role(&admin, &emergency, &Role::EmergencyOfficer);
    client.set_role(&admin, &manager, &Role::AssetManager);

    let allowed =
        client.check_compliance_transition(&emergency, &investor, &ComplianceStatus::Approved);
    assert!(allowed.allowed);

    let refused =
        client.check_compliance_transition(&manager, &investor, &ComplianceStatus::Approved);
    assert!(!refused.allowed);
    assert_eq!(refused.reason, TransitionGuard::CallerUnauthorized);
}

#[test]
fn test_batch_guard_matches_batch_execution_when_every_entry_is_legal() {
    let (env, client, admin, officer, investor) = setup_guard_world();
    let second = Address::generate(&env);
    seed_status(&client, &admin, &investor, ComplianceStatus::Pending);

    let updates = vec![
        &env,
        ComplianceBatchUpdate {
            user: investor.clone(),
            new_status: ComplianceStatus::Approved,
        },
        ComplianceBatchUpdate {
            user: second.clone(),
            new_status: ComplianceStatus::Pending,
        },
    ];

    let checks = client.check_compliance_batch(&officer, &updates);
    assert_eq!(checks.len(), 2);
    for index in 0..checks.len() {
        assert!(checks.get(index).unwrap().allowed);
    }

    assert_eq!(client.batch_set_compliance_status(&officer, &updates), 2);
    assert_eq!(
        client.get_compliance_status(&investor),
        ComplianceStatus::Approved
    );
    assert_eq!(
        client.get_compliance_status(&second),
        ComplianceStatus::Pending
    );
}

#[test]
fn test_batch_guard_flags_the_offending_entry_and_the_batch_fails_atomically() {
    let (env, client, admin, officer, investor) = setup_guard_world();
    let blocked = Address::generate(&env);
    seed_status(&client, &admin, &investor, ComplianceStatus::Pending);
    seed_status(&client, &admin, &blocked, ComplianceStatus::Blocked);

    let updates = vec![
        &env,
        ComplianceBatchUpdate {
            user: investor.clone(),
            new_status: ComplianceStatus::Approved,
        },
        ComplianceBatchUpdate {
            user: blocked.clone(),
            new_status: ComplianceStatus::Approved,
        },
    ];

    // The guard pinpoints *which* row is the problem — the batch entrypoint
    // itself can only report a single error for the whole call.
    let checks = client.check_compliance_batch(&officer, &updates);
    assert!(checks.get(0).unwrap().allowed);
    let offending = checks.get(1).unwrap();
    assert!(!offending.allowed);
    assert_eq!(offending.reason, TransitionGuard::BlockedRequiresAdmin);

    // A single rejected row fails the whole batch, and the legal row is not
    // applied: pre-flight `allowed` on row 0 is a statement about the rule,
    // not a promise that the row commits.
    let result = client.try_batch_set_compliance_status(&officer, &updates);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));
    assert_eq!(
        client.get_compliance_status(&investor),
        ComplianceStatus::Pending
    );
    assert_eq!(
        client.get_compliance_status(&blocked),
        ComplianceStatus::Blocked
    );
}

#[test]
fn test_batch_guard_flags_duplicate_addresses() {
    let (env, client, _admin, officer, investor) = setup_guard_world();

    let updates = vec![
        &env,
        ComplianceBatchUpdate {
            user: investor.clone(),
            new_status: ComplianceStatus::Pending,
        },
        ComplianceBatchUpdate {
            user: investor.clone(),
            new_status: ComplianceStatus::Approved,
        },
    ];

    let checks = client.check_compliance_batch(&officer, &updates);
    // The first occurrence is judged on its own merits; only the repeat is
    // flagged, so a client can point at the row to remove.
    assert!(checks.get(0).unwrap().allowed);
    let duplicate = checks.get(1).unwrap();
    assert!(!duplicate.allowed);
    assert_eq!(duplicate.reason, TransitionGuard::DuplicateUserInBatch);
    assert_eq!(
        duplicate.error_code,
        Some(Error::InvalidComplianceTransition as u32)
    );

    assert_eq!(
        client.try_batch_set_compliance_status(&officer, &updates),
        Err(Ok(Error::InvalidComplianceTransition))
    );
    assert_eq!(
        client.get_compliance_status(&investor),
        ComplianceStatus::Unknown
    );
}

#[test]
fn test_batch_guard_accepts_an_empty_batch() {
    let (env, client, _admin, officer, _investor) = setup_guard_world();
    let updates = vec![&env];

    assert_eq!(client.check_compliance_batch(&officer, &updates).len(), 0);
    assert_eq!(client.batch_set_compliance_status(&officer, &updates), 0);
}

#[test]
fn test_guard_agrees_with_the_legacy_whitelist_entrypoints() {
    // `whitelist_user` / `revoke_whitelist` are tolerant wrappers, but they
    // share the guard's authority rules. The guard must therefore predict
    // their *authorization* outcome exactly, even where their no-op tolerance
    // makes the transition itself a success.
    for from in ALL_STATUSES {
        let (env, client, admin, officer, investor) = setup_guard_world();
        seed_status(&client, &admin, &investor, from);

        let check =
            client.check_compliance_transition(&officer, &investor, &ComplianceStatus::Approved);
        let result = client.try_whitelist_user(&officer, &investor);

        if check.reason.is_authorization_failure() {
            assert_eq!(result, Err(Ok(Error::Unauthorized)), "from {from:?}");
        } else if from == ComplianceStatus::Approved {
            // Already approved: the guard calls it a no-op, the legacy wrapper
            // absorbs it as an idempotent success.
            assert_eq!(check.reason, TransitionGuard::StatusUnchanged);
            assert!(result.is_ok());
        } else {
            assert!(check.allowed, "from {from:?}");
            assert!(result.is_ok());
            assert_eq!(
                client.get_compliance_status(&investor),
                ComplianceStatus::Approved
            );
        }
        let _ = &env;
    }
}

// ─── ISSUER ROLE SEPARATION ───────────────────────────────────────────────────
//
// Separation of duties for issuance: the party that decides *who may hold* the
// asset must not also be the party that decides *who receives* it. The base
// role model allows exactly that overlap — the admin bypasses every role
// check, so one key can clear an investor and then fund them — so these tests
// cover the opt-in policy that closes it and, just as importantly, that the
// policy is inert until an admin turns it on. The model is documented in
// docs/issuer-role-separation.md.

/// The strictest policy: every separation control engaged.
fn strict_policy() -> IssuerSeparationPolicy {
    IssuerSeparationPolicy {
        enforced: true,
        allow_dual_duty_issuance: false,
        allow_self_issuance: false,
        require_independent_approver: true,
    }
}

/// Separation enforced, but only the named control engaged. Lets each control
/// be tested in isolation, so a passing test cannot be explained by a
/// different rule doing the work.
fn policy_with(
    dual_duty: bool,
    self_issuance: bool,
    independent_approver: bool,
) -> IssuerSeparationPolicy {
    IssuerSeparationPolicy {
        enforced: true,
        allow_dual_duty_issuance: dual_duty,
        allow_self_issuance: self_issuance,
        require_independent_approver: independent_approver,
    }
}

/// An initialized, Active contract with a compliance officer and an asset
/// manager whose duties do not overlap.
fn setup_issuer_world() -> (
    Env,
    AegisContractClient<'static>,
    Address,
    Address,
    Address,
    Address,
) {
    let (env, client, admin, officer, investor) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);
    let manager = Address::generate(&env);
    client.set_role(&admin, &officer, &Role::ComplianceOfficer);
    client.set_role(&admin, &manager, &Role::AssetManager);
    client.set_compliance_status(&officer, &investor, &ComplianceStatus::Approved);
    (env, client, admin, officer, manager, investor)
}

#[test]
fn test_issuer_separation_is_off_by_default() {
    // Adding the module must not change any existing deployment. The default
    // policy is fully permissive and is what an un-configured contract reports.
    let (_env, client, admin, _officer, manager, investor) = setup_issuer_world();

    let policy = client.get_issuer_separation_policy();
    assert!(!policy.enforced);
    assert!(policy.allow_dual_duty_issuance);
    assert!(policy.allow_self_issuance);
    assert!(!policy.require_independent_approver);

    // Every caller that could mint before still can: a scoped manager and the
    // admin.
    client.mint_asset(&manager, &investor, &10);
    client.mint_asset(&admin, &investor, &10);
    assert_eq!(client.get_balance_of(&investor), 20);

    // And a caller that could not mint before still cannot, for the same
    // reason as before (the role check, not the separation policy).
    let emergency = Address::generate(&_env);
    client.set_role(&admin, &emergency, &Role::EmergencyOfficer);
    assert_eq!(
        client.try_mint_asset(&emergency, &investor, &10),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn test_role_duty_table_is_exact() {
    let (env, client, admin, officer, manager, _investor) = setup_issuer_world();

    assert_eq!(client.get_role_duties(&Role::None), vec![&env]);
    assert_eq!(
        client.get_role_duties(&Role::ComplianceOfficer),
        vec![&env, IssuerDuty::Compliance]
    );
    assert_eq!(
        client.get_role_duties(&Role::AssetManager),
        vec![&env, IssuerDuty::Issuance]
    );
    // Derived from what the contract enforces: `mint_asset` requires
    // `AssetManager` specifically, so the emergency role carries compliance
    // and the pause switch but *not* issuance.
    assert_eq!(
        client.get_role_duties(&Role::EmergencyOfficer),
        vec![&env, IssuerDuty::Compliance, IssuerDuty::Emergency]
    );
    // The admin bypasses every role check, so it carries every duty — which is
    // precisely why it is the address the dual-duty control binds.
    assert_eq!(
        client.get_role_duties(&Role::Admin),
        vec![
            &env,
            IssuerDuty::Compliance,
            IssuerDuty::Issuance,
            IssuerDuty::Emergency,
            IssuerDuty::Governance
        ]
    );

    // The admin's authority comes from `DataKey::Admin`, not from the role
    // table, so an address-keyed read must resolve it to the full duty set.
    assert_eq!(
        client.get_duties_of(&admin),
        client.get_role_duties(&Role::Admin)
    );
    assert_eq!(
        client.get_duties_of(&officer),
        vec![&env, IssuerDuty::Compliance]
    );
    assert_eq!(
        client.get_duties_of(&manager),
        vec![&env, IssuerDuty::Issuance]
    );
    assert_eq!(client.get_duties_of(&Address::generate(&env)), vec![&env]);
}

#[test]
fn test_dual_duty_issuance_is_refused_when_separation_is_enforced() {
    let (_env, client, admin, officer, manager, investor) = setup_issuer_world();
    client.set_issuer_separation_policy(&admin, &policy_with(false, true, false));

    // The admin holds every duty, so it is the address this control binds —
    // and it must bind the admin, or the separation is decorative for the most
    // powerful key on the contract.
    assert_eq!(
        client.try_mint_asset(&admin, &investor, &10),
        Err(Ok(Error::IssuanceDutyConflict))
    );
    assert_eq!(client.get_balance_of(&investor), 0);

    // The admin's other privileges are untouched: the control targets
    // *issuance* by a dual-duty key, not the key's authority in general.
    client.set_compliance_status(&admin, &investor, &ComplianceStatus::Revoked);
    client.set_compliance_status(&admin, &investor, &ComplianceStatus::Approved);

    // A single-duty issuer is unaffected — that is the intended path: the
    // admin delegates issuance to a dedicated AssetManager key.
    client.mint_asset(&manager, &investor, &10);
    assert_eq!(client.get_balance_of(&investor), 10);
    let _ = &officer;
}

#[test]
fn test_self_issuance_is_refused_when_disallowed() {
    let (_env, client, admin, officer, manager, investor) = setup_issuer_world();
    // The manager is itself an approved holder — the situation the control is
    // about: an issuance key that can legally hold the asset.
    client.set_compliance_status(&officer, &manager, &ComplianceStatus::Approved);
    client.set_issuer_separation_policy(&admin, &policy_with(true, false, false));

    assert_eq!(
        client.try_mint_asset(&manager, &manager, &10),
        Err(Ok(Error::SelfIssuanceForbidden))
    );
    assert_eq!(client.get_balance_of(&manager), 0);

    // Issuing to anyone else is untouched.
    client.mint_asset(&manager, &investor, &10);
    assert_eq!(client.get_balance_of(&investor), 10);
}

#[test]
fn test_independent_approver_control_enforces_four_eyes() {
    let (env, client, admin, officer, manager, investor) = setup_issuer_world();
    // Dual duty is tolerated here so the *approver* control is the only thing
    // that can refuse the mint below.
    client.set_issuer_separation_policy(&admin, &policy_with(true, true, true));

    // The admin clears an investor and then tries to fund them — both halves
    // of the decision in one key.
    let alice = Address::generate(&env);
    client.set_compliance_status(&admin, &alice, &ComplianceStatus::Approved);
    assert_eq!(client.get_compliance_approver(&alice), Some(admin.clone()));
    assert_eq!(
        client.try_mint_asset(&admin, &alice, &10),
        Err(Ok(Error::IssuanceApproverConflict))
    );

    // A different issuer may fund the same investor: the control is about the
    // pair, not about the investor being tainted.
    client.mint_asset(&manager, &alice, &10);
    assert_eq!(client.get_balance_of(&alice), 10);

    // And the admin may fund an investor someone else cleared.
    assert_eq!(client.get_compliance_approver(&investor), Some(officer));
    client.mint_asset(&admin, &investor, &10);
    assert_eq!(client.get_balance_of(&investor), 10);
}

#[test]
fn test_approver_record_tracks_every_approval_path() {
    let (env, client, admin, officer, _manager, investor) = setup_issuer_world();
    let second_officer = Address::generate(&env);
    client.set_role(&admin, &second_officer, &Role::EmergencyOfficer);

    // 1. set_compliance_status (recorded during setup).
    assert_eq!(
        client.get_compliance_approver(&investor),
        Some(officer.clone())
    );

    // 2. A revocation must not erase who granted the clearance being revoked.
    client.set_compliance_status(&officer, &investor, &ComplianceStatus::Revoked);
    assert_eq!(
        client.get_compliance_approver(&investor),
        Some(officer.clone())
    );

    // 3. Re-approval by a different officer overwrites it — the record is
    //    "who cleared them now", not "who ever cleared them".
    client.set_compliance_status(&second_officer, &investor, &ComplianceStatus::Approved);
    assert_eq!(
        client.get_compliance_approver(&investor),
        Some(second_officer.clone())
    );

    // 4. The legacy wrapper drives the same record.
    let bob = Address::generate(&env);
    client.whitelist_user(&officer, &bob);
    assert_eq!(client.get_compliance_approver(&bob), Some(officer.clone()));

    // 5. So does a batch update.
    let carol = Address::generate(&env);
    client.batch_set_compliance_status(
        &second_officer,
        &vec![
            &env,
            ComplianceBatchUpdate {
                user: carol.clone(),
                new_status: ComplianceStatus::Approved,
            },
        ],
    );
    assert_eq!(client.get_compliance_approver(&carol), Some(second_officer));

    // 6. An address that was never approved has no record, and a non-approving
    //    transition never creates one.
    let dave = Address::generate(&env);
    client.set_compliance_status(&officer, &dave, &ComplianceStatus::Pending);
    assert_eq!(client.get_compliance_approver(&dave), None);
}

#[test]
fn test_separation_controls_are_independent() {
    // Each control must be able to refuse on its own; a test that passes only
    // because a *different* rule fired would prove nothing.
    let (_env, client, admin, officer, _manager, _investor) = setup_issuer_world();
    client.set_compliance_status(&officer, &admin, &ComplianceStatus::Approved);

    // Enforced, but every control relaxed: nothing is refused.
    client.set_issuer_separation_policy(&admin, &policy_with(true, true, false));
    assert!(client.check_issuance_authority(&admin, &admin).allowed);

    // Dual-duty only.
    client.set_issuer_separation_policy(&admin, &policy_with(false, true, false));
    assert_eq!(
        client.check_issuance_authority(&admin, &admin).reason,
        IssuanceGuard::DualDutyConflict
    );

    // Self-issuance only.
    client.set_issuer_separation_policy(&admin, &policy_with(true, false, false));
    assert_eq!(
        client.check_issuance_authority(&admin, &admin).reason,
        IssuanceGuard::SelfIssuanceForbidden
    );

    // Approver only — the compliance officer cleared the admin, not the admin
    // itself, so this pair is clean.
    client.set_issuer_separation_policy(&admin, &policy_with(true, true, true));
    assert!(client.check_issuance_authority(&admin, &admin).allowed);

    // ...and dirty once the admin re-clears itself.
    client.set_compliance_status(&admin, &admin, &ComplianceStatus::Revoked);
    client.set_compliance_status(&admin, &admin, &ComplianceStatus::Approved);
    assert_eq!(
        client.check_issuance_authority(&admin, &admin).reason,
        IssuanceGuard::ApproverConflict
    );
}

#[test]
fn test_missing_issuance_duty_is_reported_separately_from_a_separation_failure() {
    let (_env, client, admin, officer, manager, investor) = setup_issuer_world();
    client.set_issuer_separation_policy(&admin, &strict_policy());

    // A compliance officer is not an issuer at all: an RBAC failure, not a
    // separation one. A client must be able to tell "you are not an issuer"
    // from "you are an issuer, but not for this recipient".
    let rbac = client.check_issuance_authority(&officer, &investor);
    assert!(!rbac.allowed);
    assert_eq!(rbac.reason, IssuanceGuard::MissingIssuanceDuty);
    assert!(!rbac.reason.is_separation_failure());
    assert_eq!(rbac.error_code, Some(Error::Unauthorized as u32));

    let separation = client.check_issuance_authority(&admin, &investor);
    assert!(separation.reason.is_separation_failure());
    assert_eq!(separation.reason, IssuanceGuard::DualDutyConflict);

    // The scoped manager is the caller the strict policy is designed around.
    assert!(client.check_issuance_authority(&manager, &investor).allowed);
}

#[test]
fn test_check_issuance_authority_matches_mint_enforcement() {
    // The read and the write path must never disagree: a dashboard that
    // disables an action on the strength of this read would otherwise be
    // wrong in exactly the cases that matter.
    let policies = [
        policy_with(true, true, false),
        policy_with(false, true, false),
        policy_with(true, false, false),
        policy_with(true, true, true),
        strict_policy(),
    ];

    for policy in policies {
        let (env, client, admin, officer, manager, investor) = setup_issuer_world();
        let emergency = Address::generate(&env);
        client.set_role(&admin, &emergency, &Role::EmergencyOfficer);
        // Every address that appears as a recipient below is compliance-
        // approved, so the only thing that can refuse a mint here is a
        // separation control — which is what this test is about.
        for holder in [&emergency, &manager, &admin, &officer] {
            client.set_compliance_status(&officer, holder, &ComplianceStatus::Approved);
        }
        client.set_issuer_separation_policy(&admin, &policy);

        for caller in [&admin, &manager, &emergency, &officer] {
            for recipient in [&investor, caller] {
                let check = client.check_issuance_authority(caller, recipient);
                let balance_before = client.get_balance_of(recipient);
                let result = client.try_mint_asset(caller, recipient, &10);

                match result {
                    Ok(_) => {
                        assert!(
                            check.allowed,
                            "guard refused with {:?} but the mint succeeded",
                            check.reason
                        );
                        assert_eq!(client.get_balance_of(recipient), balance_before + 10);
                    }
                    Err(Ok(err)) => {
                        assert!(
                            !check.allowed,
                            "guard allowed but the mint reverted with {err:?}"
                        );
                        assert_eq!(check.error_code, Some(err as u32));
                        assert_eq!(client.get_balance_of(recipient), balance_before);
                    }
                    Err(Err(err)) => panic!("unexpected host error: {err:?}"),
                }
            }
        }
    }
}

#[test]
fn test_issuance_check_reports_a_consistent_snapshot() {
    let (env, client, admin, officer, _manager, investor) = setup_issuer_world();
    client.set_issuer_separation_policy(&admin, &strict_policy());

    let check = client.check_issuance_authority(&admin, &investor);
    assert_eq!(check.caller, admin);
    assert_eq!(check.recipient, investor);
    assert_eq!(check.caller_role, Role::Admin);
    assert_eq!(
        check.caller_duties,
        vec![
            &env,
            IssuerDuty::Compliance,
            IssuerDuty::Issuance,
            IssuerDuty::Emergency,
            IssuerDuty::Governance
        ]
    );
    assert_eq!(check.recipient_approver, Some(officer));
    assert!(!check.allowed);
    assert_eq!(check.reason, IssuanceGuard::DualDutyConflict);
    assert_eq!(check.error_code, Some(Error::IssuanceDutyConflict as u32));
}

#[test]
fn test_issuance_reads_never_mutate_state() {
    let (env, client, admin, _officer, manager, investor) = setup_issuer_world();
    client.set_issuer_separation_policy(&admin, &strict_policy());

    for caller in [&admin, &manager, &investor] {
        client.check_issuance_authority(caller, &investor);
        client.get_duties_of(caller);
        client.get_compliance_approver(caller);
    }

    assert_eq!(client.get_balance_of(&investor), 0);
    assert_eq!(client.get_total_supply(), 0);
    assert_eq!(client.get_role_of(&manager), Role::AssetManager);
    assert_eq!(client.get_issuer_separation_policy(), strict_policy());
    // A pre-flight read is not an issuance and must leave no audit trace.
    // `env.events().all()` reports the most recent invocation's events, which
    // for a pure read is nothing at all.
    assert_eq!(env.events().all(), vec![&env]);
}

#[test]
fn test_policy_update_is_admin_only_and_emits_the_previous_policy() {
    let (env, client, admin, officer, manager, _investor) = setup_issuer_world();

    for caller in [&officer, &manager] {
        assert_eq!(
            client.try_set_issuer_separation_policy(caller, &strict_policy()),
            Err(Ok(Error::Unauthorized))
        );
    }
    assert!(!client.get_issuer_separation_policy().enforced);

    client.set_issuer_separation_policy(&admin, &strict_policy());
    // Both policies are emitted so an auditor can reconstruct when each
    // control came into force without replaying storage.
    assert_eq!(
        env.events().all(),
        vec![
            &env,
            (
                client.address.clone(),
                ("issuer_separation_policy_updated",).into_val(&env),
                IssuerSeparationPolicyUpdatedEvent {
                    admin: admin.clone(),
                    previous_policy: IssuerSeparationPolicy::default_policy(),
                    new_policy: strict_policy(),
                }
                .into_val(&env),
            ),
        ]
    );
    assert_eq!(client.get_issuer_separation_policy(), strict_policy());
}

#[test]
fn test_policy_update_is_blocked_while_paused() {
    let (_env, client, admin, _officer, _manager, _investor) = setup_issuer_world();
    client.pause(&admin);

    assert_eq!(
        client.try_set_issuer_separation_policy(&admin, &strict_policy()),
        Err(Ok(Error::ContractPaused))
    );
    assert!(!client.get_issuer_separation_policy().enforced);

    // The read stays available while paused, so a dashboard can still explain
    // the configured controls during an incident.
    client.unpause(&admin);
    client.set_issuer_separation_policy(&admin, &strict_policy());
    assert!(client.get_issuer_separation_policy().enforced);
}

#[test]
fn test_separation_policy_can_never_lock_a_deployment_out_of_issuance() {
    // The strictest policy blocks the admin from issuing. That must be
    // recoverable: `set_issuer_separation_policy` is deliberately not gated by
    // the policy it sets, so the admin can always relax a rule that turns out
    // to be too strict.
    let (env, client, admin, officer, _manager, investor) = setup_issuer_world();
    client.set_issuer_separation_policy(&admin, &strict_policy());

    // Revoke the only independent issuer, leaving no key able to mint.
    let lone_manager = Address::generate(&env);
    client.set_role(&admin, &lone_manager, &Role::AssetManager);
    client.remove_role(&admin, &lone_manager);
    assert_eq!(
        client.try_mint_asset(&admin, &investor, &10),
        Err(Ok(Error::IssuanceDutyConflict))
    );

    // Recovery: relax the policy, then issue.
    client.set_issuer_separation_policy(&admin, &IssuerSeparationPolicy::default_policy());
    client.mint_asset(&admin, &investor, &10);
    assert_eq!(client.get_balance_of(&investor), 10);
    let _ = &officer;
}

#[test]
fn test_yield_distribution_respects_the_duty_control_only() {
    let (_env, client, admin, officer, manager, _investor) = setup_issuer_world();
    // Every recipient-scoped control is engaged; none can apply to a call with
    // no beneficiary, so only the duty control may bind here.
    client.set_issuer_separation_policy(&admin, &strict_policy());

    assert_eq!(
        client.try_distribute_yield(&admin, &100),
        Err(Ok(Error::IssuanceDutyConflict))
    );
    client.distribute_yield(&manager, &100);
    let _ = &officer;
}

#[test]
fn test_issuance_guard_reports_not_initialized_instead_of_panicking() {
    let (env, client, admin, _user1, investor) = setup();
    env.mock_all_auths();

    let check = client.check_issuance_authority(&admin, &investor);
    assert!(!check.allowed);
    assert_eq!(check.reason, IssuanceGuard::NotInitialized);
    assert_eq!(check.error_code, Some(Error::NotInitialized as u32));
    assert_eq!(check.caller_role, Role::None);
    // The policy read is equally safe before initialization.
    assert!(!client.get_issuer_separation_policy().enforced);
}

#[test]
fn test_transfer_reverts_when_sender_blocked() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);

    // Whitelist and mint to sender
    client.set_role(&admin, &admin, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&admin, &user1, &100);

    // Block sender
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Blocked);

    let bal_before = client.balance(&user1);

    let result = client.try_transfer(&user1, &user2, &50);
    assert_eq!(result, Err(Ok(Error::SenderNotWhitelisted))); // Or maybe it gives SenderBlocked? Wait, the issue says restrictions.rs returns SenderNotCompliant -> SenderNotWhitelisted. Wait, we should check `Error::SenderNotWhitelisted`. Let's just match what `try_transfer` returns.

    let bal_after = client.balance(&user1);
    assert_eq!(bal_before, bal_after, "State must remain consistent");
}

#[test]
fn test_transfer_reverts_when_sender_pending() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);

    client.set_role(&admin, &admin, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&admin, &user1, &100);

    // Pending sender
    client.set_compliance_status(&admin, &user1, &ComplianceStatus::Pending);

    let bal_before = client.balance(&user1);

    let result = client.try_transfer(&user1, &user2, &50);
    assert_eq!(result, Err(Ok(Error::SenderNotWhitelisted)));

    let bal_after = client.balance(&user1);
    assert_eq!(bal_before, bal_after, "State must remain consistent");
}

#[test]
fn test_transfer_reverts_when_receiver_blocked() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);
    client.set_asset_status(&admin, &AssetStatus::Active);

    client.set_role(&admin, &admin, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);
    client.mint_asset(&admin, &user1, &100);

    // Block receiver
    client.set_compliance_status(&admin, &user2, &ComplianceStatus::Blocked);

    let bal_before = client.balance(&user1);

    let result = client.try_transfer(&user1, &user2, &50);
    assert_eq!(result, Err(Ok(Error::ReceiverNotWhitelisted)));

    assert_eq!(
        bal_before,
        client.balance(&user1),
        "State must remain consistent"
    );
}

#[test]
fn test_transfer_reverts_when_asset_paused() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    client.set_role(&admin, &admin, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);

    // Set to Active then mint, then pause
    client.set_asset_status(&admin, &AssetStatus::Active);
    client.mint_asset(&admin, &user1, &100);
    client.set_asset_status(&admin, &AssetStatus::Paused);

    let bal_before = client.balance(&user1);
    let result = client.try_transfer(&user1, &user2, &50);
    assert_eq!(result, Err(Ok(Error::AssetPausedRestriction)));
    assert_eq!(
        bal_before,
        client.balance(&user1),
        "State must remain consistent"
    );
}

#[test]
fn test_transfer_reverts_when_asset_restricted() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    client.set_role(&admin, &admin, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);

    client.set_asset_status(&admin, &AssetStatus::Active);
    client.mint_asset(&admin, &user1, &100);
    client.set_asset_status(&admin, &AssetStatus::Blocked);

    let bal_before = client.balance(&user1);
    let result = client.try_transfer(&user1, &user2, &50);
    assert_eq!(result, Err(Ok(Error::AssetBlockedRestriction)));
    assert_eq!(
        bal_before,
        client.balance(&user1),
        "State must remain consistent"
    );
}

#[test]
fn test_transfer_reverts_when_contract_paused() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    client.set_role(&admin, &admin, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);

    client.set_asset_status(&admin, &AssetStatus::Active);
    client.mint_asset(&admin, &user1, &100);

    client.pause(&admin); // Unauthorised transfer states

    let bal_before = client.balance(&user1);
    let result = client.try_transfer(&user1, &user2, &50);
    assert_eq!(result, Err(Ok(Error::ContractPaused)));
    assert_eq!(
        bal_before,
        client.balance(&user1),
        "State must remain consistent"
    );
}

#[test]
fn test_transfer_succeeds() {
    let (env, client, admin, user1, user2) = setup();
    env.mock_all_auths();
    client.initialize(&admin);

    client.set_role(&admin, &admin, &Role::AssetManager);
    client.whitelist_user(&admin, &user1);
    client.whitelist_user(&admin, &user2);

    client.set_asset_status(&admin, &AssetStatus::Active);
    client.mint_asset(&admin, &user1, &100);

    let bal_before_sender = client.balance(&user1);
    let bal_before_receiver = client.balance(&user2);

    let result = client.try_transfer(&user1, &user2, &50);
    assert!(result.is_ok());

    assert_eq!(client.balance(&user1), bal_before_sender - 50);
    assert_eq!(client.balance(&user2), bal_before_receiver + 50);
}
