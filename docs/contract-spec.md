# Contract API Specification

> Every revert below is a standardized `Error` code, not a message string.
> See [`docs/error-codes.md`](error-codes.md) for the full code table and
> SDK/dashboard mapping guidance. See [`docs/events.md`](events.md) for the
> full event topic/payload schema and compatibility guarantees.

## Initialization

* `initialize(env, admin)`: Sets the initial admin and grants them the Admin role. Reverts with `AlreadyInitialized` if already initialized.

## Role Management (admin.rs)

* `set_role(env, admin, target, role)`: Assigns a role to `target`. Requires Admin role (`Unauthorized`). Cannot assign the Admin role — use `transfer_admin` instead (`CannotAssignAdminRole`). Emits `RoleAssignedEvent`.
* `remove_role(env, admin, target)`: Revokes the role from `target`. Requires Admin role (`Unauthorized`). Reverts with `NoRoleToRevoke` if target has no role. Emits `RoleRevokedEvent`.
* `get_role_of(env, address)`: Returns the role assigned to `address`, or `Role::None`.
* `transfer_admin(env, admin, candidate)`: Initiates a 2-step admin transfer. Requires Admin role (`Unauthorized`). Emits `AdminTransferInitiatedEvent`.
* `accept_admin(env, candidate)`: Completes a 2-step admin transfer. Reverts with `NoPendingAdminTransfer` if none is in flight, or `NotPendingCandidate` if the caller isn't the recorded candidate. Emits `AdminTransferredEvent`.
* `renounce_admin(env, admin)`: The admin renounces their own role. Requires Admin role (`Unauthorized`). Irreversible. Emits `AdminTransferredEvent`.

Any call above made before `initialize` reverts with `NotInitialized`.

## Emergency Pause (admin.rs)

* `pause(env, caller)`: Pauses the contract. Requires Admin or EmergencyOfficer role (`Unauthorized`). Reverts with `AlreadyPaused` if already paused. Emits `ContractPausedEvent`.
* `unpause(env, caller)`: Unpauses the contract. Requires Admin role only (`Unauthorized`). Reverts with `NotPaused` if not paused. Emits `ContractUnpausedEvent`.
* `is_paused(env)`: Returns whether the contract is currently paused. Always available.
* All state-changing calls listed on this page revert with `ContractPaused` while the contract is paused.

## Compliance Lifecycle (compliance.rs)

Investor compliance is a five-state lifecycle — `Unknown`, `Pending`,
`Approved`, `Revoked`, `Blocked` — with an enforced transition matrix. See
[`docs/compliance-lifecycle.md`](compliance-lifecycle.md) for the full state
table, matrix, and authorization rules.

* `set_compliance_status(env, caller, user, new_status)`: Moves `user` to `new_status`, validated against the transition matrix. Requires ComplianceOfficer, EmergencyOfficer, or Admin — except when the address is currently `Blocked`, where only the supreme admin may act (`Unauthorized`). Reverts with `ComplianceStatusUnchanged` for a no-op or `InvalidComplianceTransition` for an illegal transition. Blocked when paused (`ContractPaused`). Emits `ComplianceStatusChangedEvent`.
* `whitelist_user(env, admin, user)`: Legacy alias for a transition to `Approved`. Requires ComplianceOfficer role (or Admin) (`Unauthorized`). Blocked when paused (`ContractPaused`). Reverts with `InvalidComplianceTransition` if `user` is `Blocked`. Idempotent when already `Approved`. Emits `ComplianceStatusChangedEvent` (on a real transition) and always `UserWhitelistedEvent`.
* `revoke_whitelist(env, admin, user)`: Legacy alias for a transition to `Revoked`. Requires ComplianceOfficer role (or Admin) (`Unauthorized`). Blocked when paused (`ContractPaused`). A tolerated no-op for `Unknown` and `Blocked` addresses. Emits `ComplianceStatusChangedEvent` (on a real transition) and always `WhitelistRevokedEvent`.

### Compliance reads

Pure reads; never mutate state, require no authorization, and remain available before `initialize` and while paused.

* `get_compliance_status(env, user)`: Returns the address's `ComplianceStatus` (`Unknown` when no record exists).
* `is_compliance_transition_allowed(env, from, to)`: Returns whether `from -> to` is permitted by the matrix.
* `get_allowed_transitions(env, from)`: Returns every state reachable from `from` in one transition.
* `get_allowed_transitions_for(env, user)`: The same, for `user`'s current state.

## Asset Operations (asset.rs)


* `mint_asset(env, admin, to, amount)`: Mints `amount` to `to`. Requires AssetManager role (or Admin) (`Unauthorized`). Reverts with `InvalidAmount` if `amount <= 0`, or `AssetNotActive` if the asset lifecycle status is not `Active`. The receiver must be `Approved` under the compliance lifecycle — otherwise reverts with `ReceiverNotWhitelisted` (`Unknown`/`Revoked`), `ReceiverCompliancePending` (`Pending`), or `ReceiverBlocked` (`Blocked`). Blocked when paused (`ContractPaused`). Emits `AssetMintedEvent` (includes the running `total_supply`).
* `transfer(env, from, to, amount)`: Moves `amount` between addresses. Requires `from` auth. Reverts with `InvalidAmount` if `amount <= 0`; `AssetNotActive` if the asset is not `Active`; `InsufficientBalance` if `from` cannot cover `amount`. Both parties must be `Approved` — otherwise reverts with `SenderNotWhitelisted`/`SenderCompliancePending`/`SenderBlocked` or the corresponding receiver code. The sender is checked before the receiver. Blocked when paused (`ContractPaused`). Emits `TransferEvent` on success only — a compliance-blocked transfer reverts and emits nothing; see [`docs/events.md`](events.md#transfer-restriction-events).

* `mint_asset(env, admin, to, amount)`: Mints `amount` to `to`. Requires AssetManager role (or Admin) (`Unauthorized`). Reverts with `InvalidAmount` if `amount <= 0`; `SupplyCapExceeded` (`5002`) if minting would exceed the active global supply cap; `ReceiverNotWhitelisted` if `to` is not whitelisted. Blocked when paused (`ContractPaused`). Emits `AssetMintedEvent` (includes the running `total_supply`).
* `transfer(env, from, to, amount)`: Moves `amount` between addresses. Requires `from` auth. Reverts with `InvalidAmount` if `amount <= 0`; `SenderNotWhitelisted` or `ReceiverNotWhitelisted` if either party is not whitelisted; `InsufficientBalance` (`5001`) if `from` cannot cover `amount`; `HoldingCapExceeded` (`5003`) if the receiver's balance would exceed the active holding cap. Blocked when paused (`ContractPaused`). Emits `TransferEvent` on success only — a compliance-blocked transfer reverts and emits nothing; see [`docs/events.md`](events.md#transfer-restriction-events).

* `distribute_yield(env, admin, amount)`: Triggers a dividend yield event for off-chain indexing. Requires AssetManager role (or Admin) (`Unauthorized`). Reverts with `InvalidAmount` if `amount <= 0`. Blocked when paused (`ContractPaused`). Emits `YieldDistributedEvent`.

## Supply Cap Governance (supply_cap.rs)

* `get_supply_cap(env)`: Returns the active global supply cap (`0` = unbounded).
* `get_pending_supply_cap(env)`: Returns the pending proposed cap (`None` if none).
* `propose_supply_cap(env, admin, proposed_cap)`: Initiates a 2-step cap amendment (`supply_cap_proposed` event). Only admin; blocked when paused. Rejects negative or no-op proposals.
* `accept_supply_cap(env, admin)`: Activates the pending cap (`supply_cap_amended` event). Only admin; blocked when paused.
* `cancel_supply_cap_proposal(env, admin)`: Discards a pending proposal. Only admin; blocked when paused.
* Enforcement (`enforce_supply_cap`): `mint_asset` calls this before increasing total supply. Reverts with `SupplyCapExceeded` (`5002`) when `total_supply + amount > cap`. A cap of `0` means no cap enforced.

## Holding Cap Governance (holding.rs)

* `get_holding_cap(env)`: Returns the active per-investor holding cap (`0` = unrestricted).
* `get_pending_holding_cap(env)`: Returns the pending proposed cap (`None` if none).
* `propose_holding_cap(env, admin, proposed_cap)`: Initiates a 2-step cap amendment (`holding_cap_proposed` event). Only admin; blocked when paused. Rejects negative or no-op proposals.
* `accept_holding_cap(env, admin)`: Activates the pending cap (`holding_cap_amended` event). Only admin; blocked when paused.
* `cancel_holding_cap_proposal(env, admin)`: Discards a pending proposal. Only admin; blocked when paused.
* Enforcement (`enforce_holding_cap`): `mint_asset` and `transfer` call this before crediting the receiver. Reverts with `HoldingCapExceeded` (`5003`) when `balance + incoming > cap`. A cap of `0` means no restriction.

## Protocol Configuration (config.rs)

* `get_protocol_config(env)`: Returns the active global `ProtocolConfig`.
* `get_pending_protocol_config(env)`: Returns the pending proposed `ProtocolConfig` (`None` if none).
* `propose_config(env, admin, proposed_config)`: Initiates a 2-step configuration amendment (`config_proposed` event). Only admin; blocked when paused. Rejects malformed configurations (e.g., negative limits).
* `accept_config(env, admin)`: Activates the pending configuration (`config_amended` event). Only admin; blocked when paused.
* `cancel_config_proposal(env, admin)`: Discards a pending proposal. Only admin; blocked when paused.

## Read Functions

These functions are always available, even when the contract is paused:

* `get_balance_of(env, address)`: Returns the token balance for an address (defaults to 0).
* `get_total_supply(env)`: Returns the global total supply (defaults to 0).
* `is_whitelisted(env, user)`: Returns whether an address is compliance-approved. Derived from the lifecycle — `true` only for `ComplianceStatus::Approved`. Prefer `get_compliance_status` for the full state.

## Configuration Read Helpers (read_helpers.rs)

Pure aggregate reads for SDK/dashboard diagnostics. They require no auth, do
not mutate state, emit no events, and remain safe before `initialize` and while
paused. See [`docs/configuration-read-helpers.md`](configuration-read-helpers.md)
for field semantics and usage guidance.

* `get_contract_config(env)`: Returns `ContractConfigRead` with initialization/admin state, pending admin, active/pending protocol config, active/pending supply and holding caps, total supply, and storage version.
* `get_role_state(env, account)`: Returns `RoleReadState` with assigned/effective role, duties, admin flag, and pending-admin flag.
* `get_pause_state(env)`: Returns `PauseReadState` with global pause, asset lifecycle status, and derived `operations_enabled`.
* `get_compliance_module_status(env)`: Returns `ComplianceModuleStatusRead` describing compliance read/lifecycle/batch/guard support and current pause state.
* `get_compliance_account_state(env, account)`: Returns `ComplianceAccountRead` with lifecycle status, whitelist compatibility flag, and derived send/receive booleans.
* `get_asset_registry_status(env)`: Returns `AssetRegistryStatusRead` with single-asset registration, lifecycle, metadata, total supply, and asset-registration event status.
* `get_storage_info(env)`: Returns `StorageVersionRead` with storage, capability-schema, and contract versions plus initialization state.
* `get_storage_version(env)`: Returns the scalar storage layout version.

## Investor Eligibility (eligibility.rs)

Pure reads that compose the checks above into single-call answers for SDK and
dashboard consumers. Never mutate state; always available, even when paused.
See [`docs/investor-eligibility.md`](investor-eligibility.md) for field
semantics and SDK usage guidance.


* `get_investor_eligibility(env, investor)`: Returns an `InvestorEligibility` struct with the investor's `compliance_status` and derived `whitelisted` flag, the contract's pause state, current balance, active holding cap, remaining holding-cap capacity, and derived `can_send`/`can_receive` flags.
* `check_transfer_eligibility(env, from, to, amount)`: Returns `true` if a transfer of `amount` from `from` to `to` would currently pass every check `transfer()` performs (pause, asset lifecycle status, compliance lifecycle status on both sides, holding cap, sender balance).

## Capability Flags (capabilities.rs)

Pure reads that advertise which modules are enabled and which protocol
behaviours are supported, for SDK/dashboard feature gating. Never mutate
state, require no authorization, and — unlike every call above — remain
available **before `initialize`** as well as while paused. See
[`docs/capabilities.md`](capabilities.md) for the full field reference, the
key registry, and versioning rules.

* `get_capabilities(env)`: Returns a `ContractCapabilities` struct describing compliance, minting, transfer, pause, metadata, and event support, plus `capability_version` / `contract_version`. Each behaviour is a `CapabilityStatus` — `Supported`, `Planned`, or `Unsupported` — alongside runtime switches (`paused`, `operations_enabled`, `supply_cap_enforced`, `holding_cap_enforced`, `metadata_configured`, `initialized`).
* `supports_capability(env, capability)`: Returns the `CapabilityStatus` for a single capability key. Unknown keys return `Unsupported` instead of reverting, so newer clients fail safe against older deployments.
* `get_capability_keys(env)`: Returns every capability key understood by this contract version.
* `check_interface_compatibility(env, client_schema_version, required_capabilities)`: Returns an `InterfaceCompatibilityReport` — whether every key in `required_capabilities` resolves to `Supported`, plus how `client_schema_version` relates to this deployment's schema version. See [`docs/interface-compatibility.md`](interface-compatibility.md).

> A capability indicates the protocol *implements* a behaviour — not that the
> caller is authorized to perform it, nor that it will succeed against current
> state. Authorization remains governed by [`docs/admin-roles.md`](admin-roles.md).

* `get_investor_eligibility(env, investor)`: Returns an `InvestorEligibility` struct with the investor's whitelist status, the contract's pause state, current balance, active holding cap, remaining holding-cap capacity, and derived `can_send`/`can_receive` flags.
* `check_transfer_eligibility(env, from, to, amount)`: Returns `true` if a transfer of `amount` from `from` to `to` would currently pass every check `transfer()` performs (pause, whitelist on both sides, holding cap, sender balance).

