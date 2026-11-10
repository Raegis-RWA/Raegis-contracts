// The legacy `Events::publish((topic,), payload)` API is used intentionally:
// docs/events.md freezes these (topic, payload) shapes as a stable off-chain
// contract, and src/test.rs asserts them exactly. Migrating to the
// `#[contractevent]` macro must preserve every emitted shape byte-for-byte.
#![allow(deprecated)]
use soroban_sdk::{contractimpl, contracttype, Address, Env, String};

use crate::admin::{is_transfers_paused, require_not_paused, require_role};
use crate::compliance;
use crate::holding;
use crate::issuer::require_issuance_authority;

use crate::restrictions::{asset_status_reason, error_for_reason, RestrictionReason};

use crate::lifecycle::{get_asset_status, AssetStatus};

use crate::supply_cap;
use crate::{AegisContract, AegisContractArgs, AegisContractClient, DataKey, Error, Role};

// ─── Events ───────────────────────────────────────────────────────────────────

/// Emitted when new RWA units are minted to a whitelisted address. This is
/// the canonical asset-issuance event: the protocol does not model a
/// separate "asset registration" step distinct from minting (see
/// `docs/events.md` for the scope note), so dashboards and indexers should
/// treat `AssetMintedEvent` as marking both the issuance and, for a
/// recipient's first mint, its effective registration as an asset holder.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AssetMintedEvent {
    pub caller: Address,
    pub to: Address,
    pub amount: i128,
    pub total_supply: i128,
}

/// Emitted on every successful transfer between two whitelisted addresses.
/// Soroban discards events from reverted invocations, so a transfer blocked
/// by `SenderNotWhitelisted` / `ReceiverNotWhitelisted` never reaches this
/// point and emits no event — the standardized error code itself is the
/// off-chain-observable signal for a compliance-restricted transfer. See
/// `docs/events.md` for details.
#[contracttype]
#[derive(Clone, Debug)]
pub struct TransferEvent {
    pub from: Address,
    pub to: Address,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct YieldDistributedEvent {
    pub caller: Address,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetMetadata {
    pub name: String,
    pub symbol: String,
    pub uri: String,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct AssetMetadataUpdatedEvent {
    pub caller: Address,
    pub name: String,
    pub symbol: String,
    pub uri: String,
}

/// Returns the current asset lifecycle status, defaulting to `Draft` when
/// none has been recorded. Pure read — shared with the capability module so
/// both report the same lifecycle state as `lifecycle::get_asset_status`.
pub fn get_asset_status_internal(env: &Env) -> AssetStatus {
    env.storage()
        .instance()
        .get(&DataKey::AssetStatus)
        .unwrap_or(AssetStatus::Draft)
}

#[allow(dead_code)]
fn transition_is_valid(from: &AssetStatus, to: &AssetStatus) -> bool {
    if from == to {
        return false;
    }

    match from {
        AssetStatus::Draft => matches!(to, AssetStatus::Active),
        AssetStatus::Active => {
            matches!(
                to,
                AssetStatus::Paused | AssetStatus::Retired | AssetStatus::Blocked
            )
        }
        AssetStatus::Paused => {
            matches!(
                to,
                AssetStatus::Active | AssetStatus::Retired | AssetStatus::Blocked
            )
        }
        AssetStatus::Retired => false,
        AssetStatus::Blocked => matches!(to, AssetStatus::Active | AssetStatus::Retired),
        AssetStatus::Draft => matches!(
            to,
            AssetStatus::Active | AssetStatus::Retired | AssetStatus::Blocked
        ),
    }
}

/// Asserts that the asset lifecycle status currently permits value movement
/// (mint or transfer).
///
/// Returns the *specific* restriction error for the blocking status —
/// `AssetPausedRestriction` (7000), `AssetRetiredRestriction` (7001), or
/// `AssetBlockedRestriction` (7002) — instead of the older, generic
/// `AssetNotActive` (6000). Each maps 1:1 onto a
/// [`RestrictionReason`](crate::restrictions::RestrictionReason) so SDKs and
/// dashboards can distinguish "try again later" from "this asset is retired".
pub fn require_asset_movable(env: &Env) -> Result<(), Error> {
    let reason = asset_status_reason(&get_asset_status_internal(env));
    match error_for_reason(&reason) {
        // Only lifecycle reasons can be produced here; `None` means Active.
        Some(err) => Err(err),
        None => {
            debug_assert!(reason == RestrictionReason::None);
            Ok(())
        }
    }
}

#[contractimpl]
impl AegisContract {
    /// Returns the current metadata snapshot for the asset.
    pub fn get_asset_metadata(env: Env) -> AssetMetadata {
        AssetMetadata {
            name: env
                .storage()
                .instance()
                .get(&DataKey::AssetName)
                .unwrap_or(String::from_str(&env, "")),
            symbol: env
                .storage()
                .instance()
                .get(&DataKey::AssetSymbol)
                .unwrap_or(String::from_str(&env, "")),
            uri: env
                .storage()
                .instance()
                .get(&DataKey::AssetMetadataUri)
                .unwrap_or(String::from_str(&env, "")),
        }
    }

    /// Updates asset metadata.
    /// Requires AssetManager role or Admin.
    /// Blocked in Retired/Blocked states.
    pub fn update_asset_metadata(
        env: Env,
        caller: Address,
        name: String,
        symbol: String,
        uri: String,
    ) -> Result<(), Error> {
        require_not_paused(&env);
        caller.require_auth();
        require_role(&env, &caller, Role::AssetManager);

        let status = get_asset_status(&env);
        if matches!(status, AssetStatus::Retired | AssetStatus::Blocked) {
            return Err(Error::AssetMetadataUpdateBlocked);
        }

        env.storage().instance().set(&DataKey::AssetName, &name);
        env.storage().instance().set(&DataKey::AssetSymbol, &symbol);
        env.storage()
            .instance()
            .set(&DataKey::AssetMetadataUri, &uri);

        env.events().publish(
            ("asset_metadata_updated",),
            AssetMetadataUpdatedEvent {
                caller,
                name,
                symbol,
                uri,
            },
        );

        Ok(())
    }

    /// Mints new RWA tokens to a whitelisted address.
    /// Requires the AssetManager role or Admin.
    /// Blocked when the contract is paused.
    pub fn mint_asset(env: Env, admin: Address, to: Address, amount: i128) -> Result<(), Error> {
        require_not_paused(&env);
        admin.require_auth();
        require_role(&env, &admin, Role::AssetManager);

        // Separation of duties: the party that decides who may hold the asset
        // must not also be the party that decides who receives it. Inert
        // unless an admin has enabled the policy, so existing deployments are
        // unaffected. See `docs/issuer-role-separation.md`.
        require_issuance_authority(&env, &admin, Some(&to));

        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        // Resolve the asset lifecycle state into a *specific* restriction
        // reason (paused / retired / blocked) rather than the generic
        // `AssetNotActive`, so clients can explain the block precisely.
        require_asset_movable(&env)?;

        // Consume the compliance lifecycle state: only an `Approved` receiver
        // may be credited. `Blocked` and `Pending` return their own error
        // codes so a client can distinguish a sanctions freeze from an
        // in-flight KYC review. See `docs/compliance-lifecycle.md`.
        compliance::require_can_receive(&env, &to)?;

        // Enforce the active supply cap before increasing total supply.
        // This is a compliance-sensitive control: it must run even for the
        // admin/AssetManager, since the cap is a protocol-level invariant.
        supply_cap::enforce_supply_cap(&env, amount)?;

        // Enforce the per-investor holding cap before crediting the receiver.
        // This is a compliance-sensitive control that applies to every mint,
        // including those performed by the admin/AssetManager.

        holding::enforce_holding_cap(&env, &to, amount)?;

        let mut balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(to.clone()))
            .unwrap_or(0);
        balance += amount;
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to.clone()), &balance);

        let mut supply: i128 = env
            .storage()
            .instance()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);
        supply += amount;
        env.storage().instance().set(&DataKey::TotalSupply, &supply);

        env.events().publish(
            ("asset_minted",),
            AssetMintedEvent {
                caller: admin,
                to,
                amount,
                total_supply: supply,
            },
        );

        Ok(())
    }

    /// Transfers tokens between two whitelisted addresses.
    /// Blocked when the contract is paused.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) -> Result<(), Error> {
        require_not_paused(&env);
        if is_transfers_paused(&env) {
            return Err(Error::ContractPaused);
        }
        from.require_auth();
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        require_asset_movable(&env)?;

        // Both parties must be `Approved` under the compliance lifecycle.
        // Sender is checked first so a blocked/pending sender is reported
        // even when the receiver is also ineligible.
        compliance::require_can_send(&env, &from)?;
        compliance::require_can_receive(&env, &to)?;

        // Enforce the per-investor holding cap before crediting the receiver.
        // Applies uniformly to transfers, so no investor can be credited
        // beyond their permitted holding.
        holding::enforce_holding_cap(&env, &to, amount)?;

        let mut from_balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(from.clone()))
            .unwrap_or(0);
        if from_balance < amount {
            return Err(Error::InsufficientBalance);
        }

        // TODO: Implement fee deduction on transfer
        from_balance -= amount;
        env.storage()
            .persistent()
            .set(&DataKey::Balance(from.clone()), &from_balance);

        let mut to_balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(to.clone()))
            .unwrap_or(0);
        to_balance += amount;
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to.clone()), &to_balance);

        env.events()
            .publish(("transfer",), TransferEvent { from, to, amount });

        Ok(())
    }

    /// Mocks the distribution of yield to current token holders.
    /// Requires the AssetManager role or Admin.
    /// Blocked when the contract is paused.
    pub fn distribute_yield(env: Env, admin: Address, amount: i128) -> Result<(), Error> {
        require_not_paused(&env);
        admin.require_auth();
        require_role(&env, &admin, Role::AssetManager);

        // Yield distribution is an issuance action with no single beneficiary,
        // so only the duty-level control applies (no self- or approver-check
        // target exists).
        require_issuance_authority(&env, &admin, None);

        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        // Mock implementation. Real-world Soroban implementation requires
        // snapshotting balances or utilizing a claim-based dividend pull pattern
        // rather than iterating over maps to avoid gas limits.
        // TODO: Implement scalable yield snapshot mechanism

        env.events().publish(
            ("yield_distributed",),
            YieldDistributedEvent {
                caller: admin,
                amount,
            },
        );

        Ok(())
    }
}
