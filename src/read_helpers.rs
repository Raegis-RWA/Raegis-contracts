//! Stable read helpers for SDK and dashboard diagnostics.
//!
//! These entrypoints intentionally aggregate existing storage-backed reads into
//! small response structs so clients can inspect configuration and runtime
//! capability state without probing write paths or requiring authorization.
//! Every helper in this module is read-only: it performs no storage writes,
//! emits no events, requires no auth, and is safe before `initialize` and while
//! the contract is paused.

use soroban_sdk::{contractimpl, contracttype, Address, Env, String, Vec};

use crate::admin;
use crate::asset::{get_asset_status_internal, AssetMetadata};
use crate::capabilities::{CapabilityStatus, CAPABILITY_SCHEMA_VERSION};
use crate::compliance::{self, ComplianceStatus};
use crate::config::{self, ProtocolConfig};
use crate::holding;
use crate::issuer::{self, IssuerDuty};
use crate::lifecycle::AssetStatus;
use crate::supply_cap;
use crate::{AegisContract, AegisContractArgs, AegisContractClient, DataKey, Role};

/// Storage layout/schema version for this contract release.
///
/// This is deliberately separate from `CAPABILITY_SCHEMA_VERSION`: capability
/// schema versioning tracks the shape of public discovery structs, while this
/// value tracks the storage layout understood by this binary. The current
/// release has a single layout and no migration history, so the safe default is
/// `1` even before initialization.
pub const STORAGE_VERSION: u32 = 1;

/// Optional address value encoded as a contract type.
///
/// `Option<T>` works for some scalar return values but is not a stable shape for
/// nested custom response structs across generated SDKs, so the aggregate read
/// structs use explicit optional enums.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptionalAddressRead {
    None,
    Some(Address),
}

/// Optional protocol configuration value encoded as a contract type.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptionalProtocolConfigRead {
    None,
    Some(ProtocolConfig),
}

/// Optional signed integer value encoded as a contract type.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptionalI128Read {
    None,
    Some(i128),
}

/// Global configuration snapshot for SDK/dashboard diagnostics.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractConfigRead {
    /// Whether `initialize` has recorded an admin.
    pub initialized: bool,
    /// Current supreme admin, or `None` before initialization / after an
    /// explicit renounce.
    pub admin: OptionalAddressRead,
    /// Pending admin candidate in the 2-step transfer flow, if any.
    pub pending_admin: OptionalAddressRead,
    /// Active protocol configuration, with module defaults when unset.
    pub protocol_config: ProtocolConfig,
    /// Pending protocol configuration proposal, if any.
    pub pending_protocol_config: OptionalProtocolConfigRead,
    /// Active global supply cap (`0` means unbounded).
    pub supply_cap: i128,
    /// Pending global supply cap proposal, if any.
    pub pending_supply_cap: OptionalI128Read,
    /// Active per-investor holding cap (`0` means unrestricted).
    pub holding_cap: i128,
    /// Pending per-investor holding cap proposal, if any.
    pub pending_holding_cap: OptionalI128Read,
    /// Current total issued supply.
    pub total_supply: i128,
    /// Current storage layout/schema version.
    pub storage_version: u32,
}

/// Role and effective-duty snapshot for a single account.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleReadState {
    /// Account being inspected.
    pub account: Address,
    /// Role stored in the RBAC table (`Role::None` when absent).
    pub assigned_role: Role,
    /// Effective role after applying supreme-admin authority. This matters
    /// because the admin's authority is sourced from `DataKey::Admin` and must
    /// remain visible even if a role-table mirror is absent or stale.
    pub effective_role: Role,
    /// Duties implied by `effective_role`, in ABI order.
    pub duties: Vec<IssuerDuty>,
    /// Whether this account is the current supreme admin.
    pub is_admin: bool,
    /// Whether this account is the pending 2-step admin-transfer candidate.
    pub is_pending_admin: bool,
}

/// Contract-wide pause/lifecycle availability snapshot.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PauseReadState {
    /// Global emergency pause flag.
    pub paused: bool,
    /// Single-asset lifecycle status.
    pub asset_status: AssetStatus,
    /// Whether the asset lifecycle status is `Active`.
    pub asset_active: bool,
    /// Derived protocol-wide operation switch: `!paused && asset_active`.
    pub operations_enabled: bool,
}

/// Static and runtime compliance-module status.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComplianceModuleStatusRead {
    /// Whether the compliance module is present in this contract build.
    pub module_enabled: bool,
    /// Whether address-level compliance status reads are supported.
    pub status_reads: CapabilityStatus,
    /// Whether lifecycle status writes are implemented.
    pub lifecycle_states: CapabilityStatus,
    /// Whether lifecycle transition guards/pre-flight checks are implemented.
    pub transition_guards: CapabilityStatus,
    /// Whether batch compliance updates are implemented.
    pub batch_updates: CapabilityStatus,
    /// Whether minting enforces receiver compliance.
    pub enforced_on_mint: bool,
    /// Whether transfers enforce sender and receiver compliance.
    pub enforced_on_transfer: bool,
    /// Whether the contract is currently globally paused. Compliance writes are
    /// blocked while this is true, but reads remain available.
    pub paused: bool,
}

/// Compliance snapshot for a single investor address.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComplianceAccountRead {
    /// Investor/account being inspected.
    pub account: Address,
    /// Full lifecycle status (`Unknown` when no record exists).
    pub status: ComplianceStatus,
    /// Backwards-compatible whitelist interpretation of `status`.
    pub whitelisted: bool,
    /// Whether this account may send under compliance rules.
    pub can_send: bool,
    /// Whether this account may receive under compliance rules.
    pub can_receive: bool,
}

/// Single-asset registry/metadata snapshot.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetRegistryStatusRead {
    /// Whether this build includes the single-asset registry/metadata module.
    pub module_enabled: bool,
    /// Whether the contract has been initialized, which is when the managed
    /// asset slot becomes administratively owned.
    pub registered: bool,
    /// Current asset lifecycle status (`Draft` by default).
    pub asset_status: AssetStatus,
    /// Current metadata snapshot, with empty strings when unset.
    pub metadata: AssetMetadata,
    /// Whether both name and symbol are non-empty.
    pub metadata_configured: bool,
    /// Current total issued supply.
    pub total_supply: i128,
    /// Whether an explicit `asset_registered` event exists. The current
    /// protocol treats minting/metadata/lifecycle as the observable registry
    /// surface, so this remains a planned event capability.
    pub asset_registered_event: CapabilityStatus,
}

/// Storage and public-interface version snapshot.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageVersionRead {
    /// Storage layout/schema version understood by this contract binary.
    pub storage_version: u32,
    /// Capability discovery schema version.
    pub capability_schema_version: u32,
    /// Semantic version of the deployed contract crate.
    pub contract_version: String,
    /// Whether storage has been initialized with an admin.
    pub initialized: bool,
}

fn read_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::Admin)
}

fn read_pending_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::AdminCandidate)
}

fn read_total_supply(env: &Env) -> i128 {
    env.storage()
        .instance()
        .get(&DataKey::TotalSupply)
        .unwrap_or(0)
}

fn optional_address(value: Option<Address>) -> OptionalAddressRead {
    match value {
        Some(address) => OptionalAddressRead::Some(address),
        None => OptionalAddressRead::None,
    }
}

fn optional_protocol_config(value: Option<ProtocolConfig>) -> OptionalProtocolConfigRead {
    match value {
        Some(config) => OptionalProtocolConfigRead::Some(config),
        None => OptionalProtocolConfigRead::None,
    }
}

fn optional_i128(value: Option<i128>) -> OptionalI128Read {
    match value {
        Some(value) => OptionalI128Read::Some(value),
        None => OptionalI128Read::None,
    }
}

fn read_asset_metadata(env: &Env) -> AssetMetadata {
    let empty = String::from_str(env, "");
    AssetMetadata {
        name: env
            .storage()
            .instance()
            .get(&DataKey::AssetName)
            .unwrap_or(empty.clone()),
        symbol: env
            .storage()
            .instance()
            .get(&DataKey::AssetSymbol)
            .unwrap_or(empty.clone()),
        uri: env
            .storage()
            .instance()
            .get(&DataKey::AssetMetadataUri)
            .unwrap_or(empty),
    }
}

fn metadata_is_configured(metadata: &AssetMetadata) -> bool {
    !metadata.name.is_empty() && !metadata.symbol.is_empty()
}

/// Builds the global configuration read response.
pub fn get_contract_config_read(env: &Env) -> ContractConfigRead {
    let admin = read_admin(env);
    ContractConfigRead {
        initialized: admin.is_some(),
        admin: optional_address(admin),
        pending_admin: optional_address(read_pending_admin(env)),
        protocol_config: config::get_config(env),
        pending_protocol_config: optional_protocol_config(config::get_pending_config(env)),
        supply_cap: supply_cap::get_supply_cap(env),
        pending_supply_cap: optional_i128(supply_cap::get_pending_supply_cap(env)),
        holding_cap: holding::get_holding_cap(env),
        pending_holding_cap: optional_i128(holding::get_pending_holding_cap(env)),
        total_supply: read_total_supply(env),
        storage_version: STORAGE_VERSION,
    }
}

/// Builds the role/duty read response for `account`.
pub fn get_role_read_state(env: &Env, account: &Address) -> RoleReadState {
    let assigned_role = admin::get_role(env, account);
    let effective_role = issuer::effective_role(env, account);
    let admin = read_admin(env);
    let pending_admin = read_pending_admin(env);

    RoleReadState {
        account: account.clone(),
        assigned_role,
        effective_role,
        duties: issuer::duties_of_role(env, &effective_role),
        is_admin: admin.map_or(false, |a| a == *account),
        is_pending_admin: pending_admin.map_or(false, |a| a == *account),
    }
}

/// Builds the pause/lifecycle read response.
pub fn get_pause_read_state(env: &Env) -> PauseReadState {
    let paused = admin::is_paused(env);
    let asset_status = get_asset_status_internal(env);
    let asset_active = asset_status == AssetStatus::Active;
    PauseReadState {
        paused,
        asset_status,
        asset_active,
        operations_enabled: !paused && asset_active,
    }
}

/// Builds the compliance module status response.
pub fn get_compliance_module_status_read(env: &Env) -> ComplianceModuleStatusRead {
    ComplianceModuleStatusRead {
        module_enabled: true,
        status_reads: CapabilityStatus::Supported,
        lifecycle_states: CapabilityStatus::Supported,
        transition_guards: CapabilityStatus::Supported,
        batch_updates: CapabilityStatus::Supported,
        enforced_on_mint: true,
        enforced_on_transfer: true,
        paused: admin::is_paused(env),
    }
}

/// Builds a compliance account read response for `account`.
pub fn get_compliance_account_read(env: &Env, account: &Address) -> ComplianceAccountRead {
    let status = compliance::get_compliance_status(env, account);
    let whitelisted = status.is_approved();
    ComplianceAccountRead {
        account: account.clone(),
        status,
        whitelisted,
        can_send: whitelisted,
        can_receive: whitelisted,
    }
}

/// Builds the single-asset registry/metadata response.
pub fn get_asset_registry_status_read(env: &Env) -> AssetRegistryStatusRead {
    let metadata = read_asset_metadata(env);
    AssetRegistryStatusRead {
        module_enabled: true,
        registered: read_admin(env).is_some(),
        asset_status: get_asset_status_internal(env),
        metadata_configured: metadata_is_configured(&metadata),
        metadata,
        total_supply: read_total_supply(env),
        asset_registered_event: CapabilityStatus::Planned,
    }
}

/// Builds the storage/interface version response.
pub fn get_storage_version_read(env: &Env) -> StorageVersionRead {
    StorageVersionRead {
        storage_version: STORAGE_VERSION,
        capability_schema_version: CAPABILITY_SCHEMA_VERSION,
        contract_version: String::from_str(env, env!("CARGO_PKG_VERSION")),
        initialized: read_admin(env).is_some(),
    }
}

// ─── Public API ───────────────────────────────────────────────────────────────

#[contractimpl]
impl AegisContract {
    /// Returns a global configuration snapshot (admin, pending governance
    /// proposals, caps, protocol config, total supply, and storage version).
    pub fn get_contract_config(env: Env) -> ContractConfigRead {
        get_contract_config_read(&env)
    }

    /// Returns role, effective role, pending-admin, and duty information for
    /// one account.
    pub fn get_role_state(env: Env, account: Address) -> RoleReadState {
        get_role_read_state(&env, &account)
    }

    /// Returns the global pause flag plus asset-lifecycle availability.
    pub fn get_pause_state(env: Env) -> PauseReadState {
        get_pause_read_state(&env)
    }

    /// Returns static and runtime status for the compliance module.
    pub fn get_compliance_module_status(env: Env) -> ComplianceModuleStatusRead {
        get_compliance_module_status_read(&env)
    }

    /// Returns compliance status and derived allow/deny booleans for one
    /// account.
    pub fn get_compliance_account_state(env: Env, account: Address) -> ComplianceAccountRead {
        get_compliance_account_read(&env, &account)
    }

    /// Returns the single-asset registry/metadata/lifecycle status.
    pub fn get_asset_registry_status(env: Env) -> AssetRegistryStatusRead {
        get_asset_registry_status_read(&env)
    }

    /// Returns storage/interface version details.
    pub fn get_storage_info(env: Env) -> StorageVersionRead {
        get_storage_version_read(&env)
    }

    /// Returns the storage layout/schema version as a scalar for lightweight
    /// clients that do not need the full `StorageVersionRead` response.
    pub fn get_storage_version(_env: Env) -> u32 {
        STORAGE_VERSION
    }
}
