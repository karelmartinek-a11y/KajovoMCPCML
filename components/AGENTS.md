# AGENTS.md

## Scope

These rules apply to every path below `components/` and strengthen the repository root contract.

## Directory boundary

- Create one logical component only in `components/<repository-key>/` where the key matches `^[a-z0-9][a-z0-9-]{2,62}$`.
- Components may also be maintained outside KajovoCML; this subtree governs only the in-repository case.
- Do not place generated components in `apps/`, `packages/` or the retired `handlers/` source pipeline.
- Do not use a KCML code or hostname as the repository key. KCML assigns identity during registration.
- Do not import source code from another component directory or from private `apps/` implementation paths.

## Required contract

- Follow the active repository-component catalog, the active source manifest schema and the current companion component catalog without reducing any of those contracts. `repository-component-1.1.json` is only a historical expectation; use a newer active version when present in `main`.
- Keep `component.kcml.json`, the source-phase `manifest.kcml.json`, package metadata, tests and evidence synchronized with executable behavior.
- Use the Node.js, ESM and pnpm versions required by the active catalog, an isolated lockfile and exact dependency versions.
- Export asynchronous `invoke(input, context)` from `src/index.ts` and provide complete lint, typecheck, test and build scripts.
- Include real architecture, threat-model and runbook evidence. Placeholders, samples represented as completion and fake digests are forbidden.

## Stateful and long-running components

KajovoCML is intended to support both request-response components and authorized stateful or long-running components. A requirement for continuous synchronization, background polling, a durable checkpoint, a component-local database, a non-HTTP protocol or runtime secret access is not by itself a blocker and must not be reduced to a short-lived `invoke` simulation.

Before implementing such a component, determine whether the active catalog and platform already provide all required contracts. Typical required capabilities include:

- a catalog-declared execution mode such as `LONG_RUNNING`;
- explicit startup, readiness, active, draining and shutdown lifecycle behavior;
- a single-active-worker lease preventing duplicate consumers during deploy and rollback;
- stable component-local persistent storage surviving restart, upgrade and rollback;
- component-scoped secret resolution through KCML Secret Manager grants;
- policy-enforced protocol egress, including TCP/TLS when HTTP fetch is insufficient;
- background heartbeat, state, Pulse, audit and monitor telemetry.

If any required shared capability is missing and the owner has explicitly approved that product capability:

1. do not create a mock, polling-on-demand substitute, undocumented server change or uncontrolled network workaround;
2. implement the missing reusable capability in a separate platform branch and PR outside `components/**`;
3. version the affected catalogs and schemas, preserve compatibility or document the approved breaking impact, and update generators, validators, SDK, runtime, deployment, monitoring, onboarding and tests as applicable;
4. run full platform CI, merge and deploy the platform change first;
5. only then create a separate component PR containing exactly one `components/<repository-key>/**` tree;
6. stop only on a genuine external blocker or missing authorization, not merely because the current platform implementation is narrower than the approved product intent.

The component PR must consume only capabilities made authoritative by the active catalog. It must not embed platform implementation into its own directory.

## Persistence boundary

- Direct access from a component to the KajovoCML PostgreSQL database or another component's datastore is forbidden unless an active catalog explicitly exposes a separately authorized capability.
- A component-local SQLite database or other isolated local store is not considered direct platform database access when it is declared by an active storage grant, mounted only into the owning component and covered by quota, backup, migration, integrity and rollback rules.
- Do not store a durable database in release-specific socket or candidate directories. Use only the stable data path supplied by the platform context.
- Other components must access the data through registered tools, endpoints or Pulse contracts, never by opening the database file or issuing raw SQL.

## Network and secret boundaries

- Use only KCML-authorized egress grants. HTTP and HTTPS use the approved HTTP egress path; stateful protocols such as IMAP must use an active catalog-approved TCP/TLS capability. Never enable uncontrolled container networking.
- Validate target, port, SNI, certificate chain, protocol limits, connection lifetime and concurrency through platform policy. Never disable TLS verification.
- Resolve secrets only through the KCML runtime secret broker and explicit component grants. Manifests may declare stable secret names but never secret values.
- Secret rotation and revocation must take effect without rebuilding the image when the active platform contract supports runtime resolution.
- Never copy a managed secret into source, a manifest, an OCI layer, GitHub Actions secrets, a new `.env` authority, a deploy receipt, logs, Pulse payloads or monitoring output.

## Dependency policy

- Use only dependencies allowed by the active catalog.
- When an approved component requires a production protocol or parser not covered by the current allowlist, treat that as a platform catalog change rather than implementing a fragile custom parser or silently omitting functionality.
- Add only the minimum audited dependencies, pin exact versions and update dependency policy, license evidence, SCA, build and compatibility tests in the separate platform PR.
- Native addons, lifecycle install scripts, binary executables and component-owned Dockerfiles remain forbidden unless a newer active catalog explicitly authorizes them.

## Runtime health

A wrapper process returning HTTP 200 is not sufficient readiness evidence for a long-running component. Health and state must reflect the actual worker and its declared dependencies, including as applicable:

- lifecycle and operational state;
- active-worker lease;
- last successful external connection;
- last successful work item;
- queue depth and retry state;
- persistent storage integrity and free space;
- secret and egress grant availability without exposing secret values;
- dependency degradation and a safely redacted last error code.

Candidate deployment must not activate a second consumer against the same external resource. Use prepare, drain, lease handoff and rollback behavior defined by the active platform contract.

## Security and lifecycle

- Never commit integration tokens, access tokens, secrets, credentials, `.env` files or runtime-generated secret material.
- Use only KCML-authorized secret grants and KCML egress paths; direct platform database access and uncontrolled outbound networking are forbidden.
- A green source PR or signed image is not registration. Deploy the immutable runtime, finalize the real manifest from `manifest.kcml.json` plus the deploy receipt, register through `/v2/component-onboardings`, resolve all gates and preserve only a nonsecret receipt.
- The integration token does not authorize GitHub writes, merge, deployment or administrative activation.
- Explicit owner authorization for a named platform capability and its necessary catalog, schema, runtime, deployment or onboarding changes satisfies the approval requirement for that stated scope. Do not request duplicate approval, but do not expand beyond that scope.

## Verification

For a clean change limited to one `components/<repository-key>/**` tree, run from the repository root:

```bash
corepack pnpm repository-catalog:check
corepack pnpm repository-components:check
```

Then run in isolated-workspace mode for that component only:

```bash
pnpm install --ignore-workspace --frozen-lockfile --ignore-scripts
pnpm lint
pnpm typecheck
pnpm test
pnpm build
node ../../scripts/onboarding/contract-test.mjs .
pnpm --ignore-workspace audit --prod --audit-level high
```

Reproducible build verification is required for clean component-only changes. Full `corepack pnpm run ci` remains mandatory whenever a diff also touches `apps/**`, `packages/**`, catalogs, schemas, generators, validators, workflows, deployment infrastructure, onboarding API or migrations.

For a long-running component also verify, as applicable:

- startup and graceful shutdown;
- restart recovery from durable checkpoints;
- single-active-worker lease;
- candidate prepare mode and drain handoff;
- storage survival through upgrade and rollback;
- secret allow, deny, rotation and revocation;
- protocol egress allow and deny cases;
- real dependency-aware readiness;
- background heartbeat, state, Pulse and audit continuity.

Never claim successful registration, readiness or activation without inspecting the corresponding KCML job and gate evidence.

## Completion Report

Every completed component creation or update report must list only verified facts and must include:

- `repository-key`
- component kind and execution mode
- changed files
- required storage, secret and egress grants
- component PR
- merge commit
- isolated test results
- component workflow run
- image reference
- image digest
- signature
- SBOM
- provenance
- deploy workflow run
- deploy receipt
- production runtime identifier
- actual runtime path or URL
- persistent storage path and integrity status when applicable
- worker lease and restart-recovery status when applicable
- onboarding job ID
- assigned KCML code
- assigned hostname
- revisions status
- readiness status
- access-token handoff status
- secret grant status without secret values
- administrator activation status
- health, heartbeat, state, control, Pulse and audit check results
- result of a real functional component scenario
- rollback availability status
- every still-open blocker

Any step that was not executed must be marked as not executed, never as successful.
