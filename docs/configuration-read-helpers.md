# Configuration read helpers

SDKs and dashboard clients often need a stable, read-only view of deployment
configuration and runtime state before they decide which transaction to build.
The helpers in `src/read_helpers.rs` provide that view without requiring auth,
without emitting events, and without mutating storage. They are safe to call
before `initialize` and while the contract is paused.

## Entry points

### `get_contract_config() -> ContractConfigRead`

Aggregates the global configuration state clients commonly need:

- `initialized`
- `admin` and `pending_admin`
- active `protocol_config` and pending protocol config proposal
- active and pending `supply_cap`
- active and pending `holding_cap`
- `total_supply`
- `storage_version`

Pending/optional fields use explicit optional enums (`OptionalAddressRead`,
`OptionalProtocolConfigRead`, `OptionalI128Read`) so generated SDKs receive a
stable contract type in nested response structs.

### `get_role_state(account) -> RoleReadState`

Returns role diagnostics for one address:

- `assigned_role`: the role stored in the RBAC table, or `Role::None`
- `effective_role`: the role after applying supreme-admin authority
- `duties`: compliance, issuance, emergency, and/or governance duties implied
  by the effective role
- `is_admin`
- `is_pending_admin`

Use this for dashboard badges and operator diagnostics. It is not an
authorization bypass; write paths still enforce the role checks at submission
time.

### `get_pause_state() -> PauseReadState`

Returns the global pause flag and asset lifecycle availability:

- `paused`
- `asset_status`
- `asset_active`
- `operations_enabled = !paused && asset_active`

This lets a client explain whether minting/transfers are blocked by the global
emergency pause, the asset lifecycle, or both.

### `get_compliance_module_status() -> ComplianceModuleStatusRead`

Returns static and runtime compliance-module status:

- module present/enabled
- address status reads supported
- lifecycle states supported
- transition guards supported
- batch updates supported
- enforcement on mint and transfer
- current global pause flag

### `get_compliance_account_state(account) -> ComplianceAccountRead`

Returns the address-keyed compliance state for one investor/operator:

- `status` (`Unknown` by default)
- backwards-compatible `whitelisted` boolean
- derived `can_send` / `can_receive` booleans

The current compliance registry is address-keyed, not enumerable. Dashboards
should query known addresses and use events/off-chain indexing for lists. See
[`compliance-registry-reads.md`](compliance-registry-reads.md).

### `get_asset_registry_status() -> AssetRegistryStatusRead`

Returns the single-asset registry/metadata snapshot:

- module present/enabled
- whether the managed asset slot is administratively registered (`initialized`)
- `asset_status`
- metadata (`name`, `symbol`, `uri`) with empty-string defaults
- `metadata_configured`
- `total_supply`
- `asset_registered_event` capability status

The current protocol manages one asset slot rather than an enumerable asset
registry. A dedicated `asset_registered` event remains a planned capability;
clients should treat lifecycle, metadata, mint, and transfer events as the
observable registry surface for this release.

### `get_storage_info() -> StorageVersionRead`

Returns:

- `storage_version`
- `capability_schema_version`
- crate `contract_version`
- `initialized`

### `get_storage_version() -> u32`

Lightweight scalar version read for clients that only need the storage layout
version.

## Client usage pattern

1. Call `get_storage_info()` and `get_capabilities()` once when connecting to a
   deployment.
2. Call `get_contract_config()`, `get_pause_state()`, and
   `get_asset_registry_status()` before rendering administrative or issuance
   controls.
3. Call `get_role_state(operator)` for the connected wallet to explain which
   actions it can attempt.
4. Call `get_compliance_account_state(investor)` for addresses the user is
   viewing or preparing to mint/transfer to.
5. Re-read runtime fields (`paused`, `asset_status`, caps, pending proposals,
   compliance status) before submitting a transaction. These helpers are
   diagnostics; state can still change between read and submit.

## Safety guarantees

All helpers in this module are pure reads:

- no storage writes
- no events
- no authorization required
- no panic on missing admin/config/metadata/status keys
- safe defaults for uninitialized deployments

Tests in `src/test.rs` cover both default and configured states and assert that
calling the helpers does not change event count, supply, or balances.
