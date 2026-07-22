# AGENTS.md

## Scope

These instructions apply to the entire repository. More specific `AGENTS.md` files may add stricter rules for their subtree, but they must not weaken this contract.

KCML is a security-focused control plane for registering, operating and auditing isolated MCP servers and managed external APIs. Treat every change as potentially security-, compatibility-, data- and deployment-sensitive until the repository proves otherwise.

## Project Lifecycle Contract

The repository lifecycle is currently `PRE_PRODUCTION_TESTING`. Treat the system as security-, compatibility-, deployment- and data-sensitive, but not yet baseline-locked for immutable production history.

While the project remains in `PRE_PRODUCTION_TESTING`:

- destructive cleanup of clearly test-only data or artifacts still requires explicit owner approval scoped to that exact change;
- any approved reset must preserve executable security controls, authorization boundaries, MFA, auditing, migration safety, onboarding validation, release signing and deploy verification;
- `PASS` remains the narrow deployment-only secret for synchronizing the deployment-managed owner account `karmar78`;
- plaintext `PASS` must never be committed, logged, returned by API, stored in app config or persisted in PostgreSQL;
- only the resulting Argon2id password hash may be persisted in `admin_account`, and the deployment-managed owner plus MFA must remain fail-closed after reset or deploy.

If the owner explicitly declares `PRODUCTION_BASELINE_LOCKED`, immediately switch to immutable preservation rules for migration history, catalogs, release evidence and audit history. After that declaration:

- do not rewrite released migrations or checksum history;
- do not delete historical onboarding catalogs or release evidence;
- do not perform destructive resets of runtime or audit history without new explicit owner approval and a documented recovery path.

Never treat any previous reset approval as standing authorization for a future unrelated destructive change.

## Source-of-truth hierarchy

Use this order when sources disagree:

1. executable source code;
2. numbered PostgreSQL migrations and their checksum ledger, except while they are being replaced by the explicitly approved pre-production baseline reset above;
3. machine-readable schemas, contracts and onboarding catalogs in `docs/onboarding-catalogs/`, except while they are being replaced by that reset;
4. catalog generators and validators;
5. automated tests that match the intended invariants;
6. active build, CI, release and deployment configuration;
7. explanatory documentation, audit matrices and comments.

Do not make code conform to stale prose. Determine the intended invariant, fix the implementation or test as appropriate, and update every newly inaccurate document or comment.

## Required repository intake

Before editing:

- inspect `README.md`, `package.json`, the relevant application/package sources, migrations, tests and runbooks;
- trace callers, callees, API contracts, persistence, authorization, audit, localization and deployment implications;
- inspect `docs/requirements-matrix.md` and `docs/audit-remediation-matrix.md` as traceability aids when they exist, then verify their claims against executable artifacts;
- inspect the current onboarding catalog, its generator, schemas and compatibility tests whenever a change can affect components, manifests, MCP, OAuth, Pulse, routes, scopes, activation, monitoring or recertification;
- preserve unrelated user work and never overwrite concurrent changes.

For the active one-time reset, perform enough intake to execute safely and derive the new baseline correctly, but do not turn intake into an attempt to invalidate the owner's already approved product decision or to preserve explicitly removable test history.

Never invent filenames, modules, commands, architectural layers or completed verification.

## Non-negotiable implementation rules

- Solve the root cause. No mocks, placeholders, hidden workarounds, status hacks or reduced-scope substitutes may be presented as completion.
- Follow existing architecture and extend shared mechanisms instead of creating parallel implementations.
- Preserve type safety, transactionality, least privilege, fail-closed behavior, auditability, idempotency and backward compatibility except for the explicitly approved breaking removal of pre-reset test contracts.
- Update every affected layer: UI, API, domain logic, persistence, migrations, authorization, audit, tests, localization, documentation, CI and deployment as applicable.
- Never weaken, skip or delete a test, security gate, catalog check, secret scan, dependency audit, CodeQL check or deployment guard merely to obtain a green result. Tests and checks that encode the deliberately removed pre-reset baseline must be replaced with equally strong checks for the new baseline rather than retained as blockers or simply disabled.
- Do not hand-edit generated catalog digests. Outside the active one-time reset, retain immutable historical catalog artifacts. During the approved reset, remove the pre-reset test catalogs as requested, generate the new baseline artifact through the repository generator and verify its canonical digest.

## GUI-first configuration and secrets

Any value that an administrator or user must create, enter, change, rotate, revoke, confirm or manage must be fully manageable through the KCML GUI and authoritative application storage.

A complete implementation includes, as relevant: UI, validation, localized help, authorized API, durable PostgreSQL persistence, encrypted secret storage, masked readback, rotation/removal, audit records, error handling and tests.

Do not introduce a new normal operational dependency on `.env`, process/system environment variables, manual server configuration, SSH edits, one-off SQL, source edits or a new GitHub Actions secret. Environment values may only serve genuine bootstrap or one-time migration needs and must not remain the user-facing authority.

The existing GitHub Actions secret `PASS` is a narrow deployment exception. Do not rename it or use it as precedent for other secrets. It may be passed only to the authorized deploy/reset process and used to derive the Argon2id hash for the deployment-managed owner account. Never expose its plaintext to the application UI or API, persist the plaintext in PostgreSQL, place it in application configuration, include it in artifacts or print it to logs.

Short-lived integration tokens used by authorized self-service onboarding are a separate category. Their full value may be displayed, logged and temporarily stored when required by the integration flow, provided scope, job/component binding, expiry and revocation are enforced and removable temporary artifacts are cleaned up. They must never be committed or included in release artifacts.

## Onboarding compatibility gate

Classify every change before implementation:

- `NO IMPACT`: demonstrably no onboarding or compatibility contract changes;
- `COMPATIBLE IMPACT`: onboarding-related change intended to remain fully backward compatible;
- `BREAKING OR POTENTIALLY BREAKING IMPACT`;
- `UNKNOWN IMPACT`.

Only `NO IMPACT` may normally proceed without explicit user approval. For every other classification, stop before implementation, commit, push, merge or deployment and obtain approval specific to that change.

The active one-time reset directive above is the specific approval for the described breaking catalog and compatibility reset. Do not request duplicate approval for work that remains within its exact scope. Any additional or unrelated catalog-impacting change still requires separate explicit approval.

A catalog impact includes direct or indirect changes to catalogs, schemas, digests, manifests, component IDs, blueprints, integration-token scopes, MCP protocol/transport/tools, JSON schemas, Pulse contracts, route ACLs, OAuth resource or audience binding, permissions, public endpoints, limits, errors, activation, monitoring, quarantine, recertification, release or runtime behavior represented by the catalog.

After ordinary approved catalog-impacting work, create a new version using the repository convention, preserve previous versions, provide migration and rollback paths, build a compatibility matrix and test every supported AI client, MCP server and managed service combination relevant to the change. For the active one-time pre-production reset, create one new verified baseline catalog and intentionally remove the prior test-only catalog lineage instead of preserving or migrating it.

## Database and migration discipline

- Outside the active one-time reset, never modify an already released numbered migration unless the repository's explicit migration policy proves it is safe and intended.
- Outside the active one-time reset, add forward migrations with the next valid number and preserve checksum-ledger behavior.
- During the approved reset, derive one complete deterministic baseline migration from the verified active schema, replace the pre-production migration chain and checksum history, and prove clean installation, schema equivalence, constraints, functions, triggers, extensions and database-role isolation.
- Verify clean install, representative upgrade where a preserved upgrade path exists, role isolation, constraints, repeated execution where required, and rollback/recovery implications.
- Application roles must not gain migration ownership or direct audit-chain mutation privileges.
- Never use manual production SQL as the permanent implementation of a repository change.

## UI work

For any UI change:

1. render and capture the current relevant states;
2. implement using existing components and localization mechanisms;
3. cover loading, empty, error, disabled, long-content and permission states;
4. verify keyboard access, focus behavior, dialog semantics, responsiveness and supported languages;
5. render the result at relevant desktop and mobile breakpoints and compare it visually;
6. repeat the visual check after deployment.

No text or control may overlap, overflow its intended container, become clipped, create unintended scrolling or break under longer translations.

## Verification

Minimum local verification before commit:

```bash
corepack pnpm install --frozen-lockfile
corepack pnpm run ci
```

Also run all relevant targeted checks, including as applicable:

```bash
corepack pnpm catalog:check
corepack pnpm db:migrate
```

Use a disposable migrated PostgreSQL database and `KCML_TEST_DATABASE=1` for database integration suites. Validate clean and upgrade migrations where relevant, role isolation, catalog generation/checks, MCP initialize/tools contracts, OAuth/audience binding, GUI configuration, secret handling, release packaging, deployment harnesses, E2E behavior and visual rendering when relevant.

For the active reset, replace tests tied solely to intentionally deleted test history with complete tests of the new baseline, lifecycle state, owner/MFA restoration and reset safety. Do not retain obsolete expectations merely to make the approved reset impossible.

Never claim that a test, CI run, release, deployment, visual review or compatibility check passed unless it was actually executed and its concrete result was inspected.

## Git, CI, release and deployment

- Review `git status` and the complete diff before committing; exclude secrets, `.env`, logs, backups, generated runtime artifacts and unrelated files.
- Use the repository's branch-protection and pull-request requirements; never force-push protected history or bypass required checks.
- Track CI after every push and fix root causes in code, tests, workflows, release scripts or environment as evidence requires.
- A push to `main` or approved manual dispatch drives release/deployment; pull requests do not deploy.
- Production-shaped releases are CI-built immutable artifacts verified by checksum and keyless Sigstore identity. Never build a deployable release in place on the server.
- Keep durable server changes reproducible in the repository. Do not leave undocumented server-only drift.
- Verify the deployed commit/build, services, migrations, logs, relevant endpoints, OAuth/MCP behavior, catalog compatibility and the changed user scenario after deployment.
- Outside the active reset, roll back only through the documented migration-compatible release procedure. The reset itself must use its approved fail-closed backup/recovery procedure and must not claim compatibility with the intentionally removed test baseline.

If more than seven consecutive CI, release or deployment attempts fail, escalate using the authorized Codex CLI environment on the server with the complete request, commits, workflow runs, logs, hypotheses and attempted fixes. Any durable fix must return to the repository and pass the standard pipeline.

## Completion report

Report only verified facts and include:

- outcome and changed files;
- architectural and security decisions;
- migrations and dependency changes;
- tests and exact results;
- onboarding impact classification and approval status;
- compatibility coverage or the explicitly approved removal of pre-reset test compatibility;
- GUI-first configuration and secret-storage assessment;
- owner `karmar78`, `PASS` synchronization and MFA verification when affected;
- lifecycle state and whether the temporary reset directive was removed as required;
- commit/PR/merge, CI, release and deployment status;
- post-deploy and visual verification where relevant;
- migration/rollback or reset recovery state;
- unresolved blockers or risks.

A partially implemented, unverified or blocked change must be labelled accordingly and must never be described as complete.
