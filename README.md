#  Raegis RWA Contracts

Core smart contract infrastructure for the Raegis RWA Protocol. Built on the Stellar network using the Soroban SDK.

## Overview
Raegis enables the fractional tokenization of Real-World Assets (RWAs). The contracts strictly enforce regulatory compliance at the ledger level, ensuring tokens can only be minted to and transferred between KYC-whitelisted addresses.

## Prerequisites
* [Rust](https://rustup.rs/) (>= 1.71)
* [Soroban CLI](https://soroban.stellar.org/docs/getting-started/setup)

## Setup & Build
1. Install the `wasm32-unknown-unknown` target:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```
2. Build the contract:
   ```bash
   make build
   ```
   
## Testing
Run the comprehensive test suite locally:
   ```bash
   make test
   ```

> Before opening a PR, run `make verify` (fmt-check + clippy + test + build) -- this is the same gate CI enforces, and failing checks can block PR approval. See the CI & Contributing section below, especially the [Failing CI Response Guide](docs/failing-ci-guide.md) and the [Low-Effort PR Examples](docs/low-effort-pr-examples.md), if anything fails.

### SDK integration fixtures
Deterministic example outputs for downstream SDK, dashboard, and indexer
repos live in [`fixtures/sdk/`](fixtures/sdk). They are generated from real
contract invocations and re-verified on every test run, so contract drift
fails CI here instead of reaching consumers. Event fixtures also assert the
exported typed payload, exact topic, caller, count, and ordering before their
JSON/XDR snapshots can be updated:
   ```bash
   make test-fixtures          # verify committed fixtures still match
   make update-fixtures        # regenerate after an intentional change
   ```
See [SDK Integration Fixtures](docs/sdk-fixtures.md) for the format, the
value-encoding rules, and the no-real-user-data guarantee.
## Security & Compliance

> **Important**: Please read our [Legal Boundary Disclaimer](docs/legal-boundary-disclaimer.md) to understand the off-chain assumptions and limitations of the RWA tokenization model.

- [Contract Storage Layout and Migration Guide](docs/storage-audit-map.md) — complete key inventory, stored data models, cross-key invariants, upgrade assumptions, migration strategies, and the mandatory storage-change review checklist
- [RWA Protocol Threat Model](docs/threat-model.md) — protected assets, trust boundaries, threat catalog (compliance bypass, admin/role misuse, minting and transfer risks, pause misuse, event reliability), and explicit off-chain/legal out-of-scope items
- [Emergency Pause Policy](docs/emergency-pause.md) — global pause mechanism, authorization, and trust model
- [Admin Roles & Permissions](docs/admin-roles.md) — role-based access control (RBAC) design
- [Issuer Role Separation](docs/issuer-role-separation.md) — separation-of-duties controls for issuance: the duty map per role, the opt-in policy (dual-duty, self-issuance, independent-approver), the `check_issuance_authority` pre-flight read, and what the controls do and do not defend against

- [Admin Misuse Risks](docs/admin-misuse-risks.md) — threat model and mitigations
- [Supply Cap Amendment Governance](docs/supply-cap-governance.md) — 2-step cap amendment workflow and enforcement
- [Protocol Configuration Governance](docs/protocol-configuration.md) — global configuration module (`ProtocolConfig`) 2-step governance workflow and RWA guardrails

- [Compliance Status Lifecycle](docs/compliance-lifecycle.md) — five-state investor lifecycle (`Unknown`/`Pending`/`Approved`/`Revoked`/`Blocked`), enforced transition matrix, authorization rules, and mint/transfer enforcement

- [Compliance Status Transitions](docs/compliance-status-transitions.md) — the approved/revoked/blocked/pending/unknown state machine, its transition matrix under authorised and unauthorised callers, and the invariant transition tests that guard it (audit readiness)


- [Compliance Status Transition Guards](docs/compliance-transition-guards.md) — the ordered guard chain every status change must clear, the typed refusal reasons (`BlockedRequiresAdmin`, `TransitionForbidden`, …), the pre-flight reads (`check_compliance_transition` / `check_compliance_batch`) that share one evaluation with enforcement, and the documented security assumptions

- [Compliance Batch Updates](docs/compliance-batch-updates.md) - atomic multi-address lifecycle updates, edge cases, event ordering, and SDK/dashboard guidance

## Errors

- [Contract Error Code Standard](docs/error-codes.md) — standardized error codes for compliance, admin, minting, transfer, and storage failures, plus SDK/dashboard mapping guidance

- [Transfer Restriction Reason Codes](docs/transfer-restrictions.md) — granular blocked-transfer reasons (non-compliant sender/recipient, paused/retired/blocked asset, cap breaches, unauthorised operation), pre-flight reason reads, and the SDK/dashboard mapping contract

- [SDK Integration Fixtures](docs/sdk-fixtures.md) — deterministic example outputs for compliance, minting, transfer, event, error, and capability scenarios, for cross-repo testing

- [Contract Capability Flags](docs/capabilities.md) — read-only descriptor of which modules and protocol behaviours a deployment supports, for SDK/dashboard feature gating

- [Public Interface Compatibility Checks](docs/interface-compatibility.md) — how SDK/dashboard clients verify their required capabilities and schema version against a deployment before integrating

- [Investor Holding Restriction Checks](docs/investor-holding-restrictions.md) — per-investor holding cap workflow and enforcement

## Investor Tooling

- [Investor Eligibility Read Helpers](docs/investor-eligibility.md) — compliance, holding-cap, and transfer eligibility read helpers for SDKs and dashboards
- [Configuration Read Helpers](docs/configuration-read-helpers.md) — aggregate read-only helpers for configuration, roles, compliance module status, asset registry status, pause state, and storage version
- [Contract Capability Flags](docs/capabilities.md) — read-only capability flags describing supported modules and protocol behaviors for SDKs and dashboards

- [Requirement Traceability Mapping](docs/traceability-mapping.md) — mandatory completion table format for PR acceptance criteria mapping, with status tracking and incomplete criteria handling
- [Compliance Registry Reads and Indexing Strategy](docs/compliance-registry-reads.md) — supported point reads, event-indexed pagination, consistency guarantees, and dashboard/SDK boundaries
- [Dashboard Integration Readiness Review](docs/dashboard-readiness-review.md) — API gaps, event limitations, and SEP-41 token compatibility risks for front-end integrations
- [Dashboard Release Readiness Review (MVP)](docs/dashboard-release-readiness.md) — UI/UX gaps, test coverage requirements, and security flow risks for the dashboard application
- [Dashboard Local Troubleshooting Guide](docs/dashboard-troubleshooting.md) — practical fixes for Freighter setup, RPC errors, and Next.js configuration

## Contributor Guides

- [Contributor Evaluation Policy](docs/contributor-evaluation-policy.md) — **formal policy** covering evaluation expectations, self-review, maintainer review standards, GrantFox evaluation, testing/CI, acceptance criteria completion, and payment-period conduct
- [Contributor Self-Review Form](docs/contributor-self-review-form.md) — **mandatory self-review** covering requirements, implementation, tests, CI, documentation, and known limitations
- [Local Deployment Guide](docs/local-deployment.md) — deployment assumptions, environment variables, Makefile reference, Soroban CLI usage, and common errors
- [Reviewer Checklist](docs/reviewer-checklist.md) — standardized quality and security checklist for PR reviewers
- [Reviewer Evidence Checklist](docs/reviewer-evidence-checklist.md) — maintainer-side evidence checklist for scope, implementation quality, tests, CI, docs, acceptance criteria, and evaluation risk
- [Contributor Experience Review](docs/contributor-experience-review.md) — known onboarding friction and follow-up items

## CI & Contributing

| Failure type | Where to look | Local fix command |
|---|---|---|
| Compilation error | `cargo build` output | `make build` |
| Test failure | `cargo test` output | `make test` |
| Formatting | unformatted files | `make fmt` (or `make fmt-check` to check only) |
| Lint warnings | `cargo clippy` output | `make clippy` |
| All of the above | full pre-push gate | `make verify` |

See [Failing CI Response Guide](docs/failing-ci-guide.md) for detailed causes and fixes per category.

- [Issue Approval Readiness Checklist](docs/issue-approval-readiness-checklist.md) — **mandatory checklist** for contributors and reviewers before considering an issue ready for evaluation
- [Evaluation Readiness Summary](docs/evaluation-readiness.md) — **central page** summarizing what makes a contribution evaluation-ready: testing standards, CI workflow, PR evidence, acceptance criteria mapping, self-review, and conduct guidance
- [PR Evidence Checklist](docs/pr-evidence-checklist.md) — **mandatory** evidence checklist for every PR: issue reference, implementation summary, tests, commands run, CI status, and acceptance criteria coverage
- [Local Verification Command](docs/local-verification.md) — run `make verify` (fmt-check + clippy + test + build) before pushing to avoid failing CI
- [Failing CI Response Guide](docs/failing-ci-guide.md) — how to reproduce and fix Rust, Soroban, Makefile, dependency, and workflow failures (failing checks can block approval)
- [Payment-Period Conduct Note](docs/payment-period-conduct.md) — contributor expectations during paid periods: no spam, self-review, GrantFox evaluation, CI/testing
- [Meaningful Implementation Checklist](docs/meaningful-implementation-checklist.md) — what counts as real contract work: behaviour, security, tests, events, acceptance criteria + reviewer checks
- [Meaningful Change Threshold Guide](docs/meaningful-change-threshold.md) — why line count alone is not the standard, small-but-complete vs. small-but-incomplete examples, and reviewer scope-assessment guidance
- [Aegis Contracts Contribution Examples](docs/aegis-contracts-examples.md) — side-by-side comparisons of low-effort, partial, under-tested, failing-CI, and acceptable contributions (reference before opening a PR)
- [Minimum Testing Standards](docs/testing-standards.md) — **mandatory** testing requirements per module, happy-path and negative-path expectations, integration fixtures, manual verification guidance, and no-test justification policy


## Contributing
Please see CONTRIBUTING.md for guidelines on how to submit pull requests, branch naming conventions, and testing requirements.
