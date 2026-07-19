# MCP compatibility forensic audit 2026-07-19

Audit request baseline: `5121f26da5a91842aa66c172a9b6c2d0c8aa8083`, treated as historical analytical context only.

Current upstream baseline verified for this pass:

- `origin/main`: `35754cfa3668fe10af7e852dbaf9f7eac5de59ac`
- `origin/main` log: `35754cf Merge pull request #53 from karelmartinek-a11y/audit/component-contract-forensics-20260719`
- local branch state at audit time: `main...origin/main [behind 3]`
- existing uncommitted candidate files were present before this document was corrected:
  - `apps/server/src/domain/mcp-policy.ts`
  - `apps/server/src/http/auth-routes.ts`
  - `apps/server/src/http/json-rpc.ts`
  - `apps/server/src/http/json-rpc.test.ts`
  - `apps/server/src/http/mcp.ts`
  - `apps/server/src/http/mcp.test.ts`
  - `apps/server/src/http/auth-routes.test.ts`

Overall onboarding compatibility classification: `UNKNOWN IMPACT`.

Current approval scope from the prompt:

- full read-only forensic audit: approved;
- evidence matrix creation: approved;
- remediation of findings classified as `NO IMPACT`: approved;
- remediation of `COMPATIBLE IMPACT`, `BREAKING OR POTENTIALLY BREAKING IMPACT`, or `UNKNOWN IMPACT`: not approved in this prompt.

Important handling note: the uncommitted runtime patch already present in the worktree touches initialize behavior, JSON-RPC notification status, cancellation, OAuth discovery metadata and JSON-RPC error metadata. Those areas are explicitly listed by the repository gate and the prompt as onboarding/catalog-impact candidates. This document therefore records them as candidate remediations waiting for specific user approval, not as completed approved changes.

Official standards checked:

- MCP 2025-11-25 lifecycle: `initialize` establishes protocol version compatibility; if the server supports the requested version it responds with that version, otherwise it responds with another supported version or a protocol error carrying supported/requested metadata.
- MCP 2025-11-25 Streamable HTTP: POST is the MCP message transport; accepted notification-only POST bodies return HTTP 202 with no body; GET either opens an SSE stream or returns HTTP 405 when no SSE stream is offered.
- MCP 2025-11-25 schema: `notifications/cancelled` can cancel an in-flight non-task request and carries the previous request id and optional reason.
- MCP 2025-11-25 authorization: protected HTTP MCP servers must expose Protected Resource Metadata and authorization server discovery; pre-registration, Client ID Metadata Documents and Dynamic Client Registration are all recognized registration approaches.
- OpenAI Responses API MCP/connectors documentation: OpenAI can call remote MCP tools through the Responses API; connector OAuth access tokens are supplied by the application and OAuth client registration/authorization is handled separately by the application.

## Traceability map

| Requirement area | Code evidence | Database/catalog evidence | Automated evidence | CI or production gate |
| --- | --- | --- | --- | --- |
| MCP endpoint and routing | `apps/server/src/http/mcp.ts`, `apps/server/src/app.ts`, `apps/server/src/index.ts` | `mcp_server.hostname`, managed-service resource binding, release constants | `apps/server/src/http/mcp.test.ts`, release smoke CLI | `.github/workflows/ci-deploy.yml`, release guard scripts |
| JSON-RPC envelope and errors | `apps/server/src/http/json-rpc.ts`, `apps/server/src/http/errors.ts` | invocation and idempotency persistence | `apps/server/src/http/json-rpc.test.ts`, `apps/server/src/http/mcp.test.ts` | `corepack pnpm run ci` |
| MCP policy, schema validation, idempotency, rate, timeout, concurrency | `apps/server/src/domain/mcp-policy.ts`, `apps/server/src/http/mcp.ts` | migrations for invocation, idempotency, leases and rate buckets | `apps/server/src/domain/mcp-policy.test.ts`, DB suites when enabled | PostgreSQL CI with `KCML_TEST_DATABASE=1` |
| OAuth and audience binding | `apps/server/src/http/auth-routes.ts`, `apps/server/src/domain/auth.ts`, `apps/server/src/domain/managed-service.ts`, `apps/server/src/domain/component-auth.ts` | token, credential, managed-service and component authorization tables | auth, managed-service and component authorization tests | release MCP smoke token flow |
| Onboarding catalog and manifest contracts | `scripts/generate-mcp-onboarding-catalog.mjs`, `apps/server/src/domain/registration.ts`, `apps/server/src/domain/release.ts` | `docs/onboarding-catalogs/component-2026.07.20.json`, `component-2026.07.21.json`, `component-2026.07.22.json`, manifest schemas | `apps/server/src/domain/catalog-contracts.test.ts`, `apps/server/src/domain/registration.test.ts` | `corepack pnpm catalog:check` |
| Activation and monitoring protocol evidence | `apps/server/src/onboarding/activation.ts`, `apps/server/src/onboarding/monitoring.ts` | monitoring profile/result, runtime log and audit tables | activation and monitoring tests | deployment and monitor services |
| GUI-first config and secrets | `apps/admin-ui/src`, `apps/server/src/domain/secret-manager.ts`, `apps/server/src/http/secret-api-routes.ts` | operational config and Secret Manager migrations | admin UI and secret-manager tests referenced by remediation matrix | CI UI build and deployment harness |

## Forensic matrix

| Control ID | Requirement | Applicability | Evidence | Status | Severity | Root cause | Compatibility impact | Remediation | Verification | Final state |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MCP-COMP-001 | MCP must remain a standard interoperable integration contract usable by OpenAI and standard MCP clients. | APPLICABLE | `/mcp`, OAuth metadata, `tools/list`, `tools/call`; no live OpenAI Responses/ChatGPT evidence in repo. | PARTIAL | HIGH | Local release smoke does not prove external OpenAI interoperability. | COMPATIBLE IMPACT for any public behavior hardening. | Run live MCP Inspector, Responses API or ChatGPT developer connection tests against deployed endpoint and credentials. | Not run locally. | BLOCKED BY OBJECTIVE EXTERNAL BLOCKER |
| MCP-COMP-002 | Use MCP, JSON-RPC 2.0, Streamable HTTP, HTTPS/TLS, JSON Schema and OAuth where protected. | APPLICABLE | MCP/OAuth code, nginx/deploy harnesses and catalog protocol fields. | PARTIAL | HIGH | Candidate runtime changes touch public protocol behavior and require approval before completion. | COMPATIBLE IMPACT. | AP-001 through AP-005 below. | Targeted candidate tests passed locally. | WAITING FOR SPECIFIC USER APPROVAL |
| MCP-COMP-003 | Streamable HTTP endpoint behavior, including POST and honest GET behavior. | APPLICABLE | Current tests protect `GET /mcp` 405 when no SSE stream is offered; official MCP 2025-11-25 allows this. | PASS | LOW | No SSE GET stream is implemented. | NO IMPACT. | No runtime change required. | Existing `mcp.test.ts`; official spec evidence. | PASS |
| MCP-COMP-004 | Transport security: Origin, DNS rebinding, localhost bind, TLS/proxy, body/rate limits and host checks. | APPLICABLE | `originAllowed`, host routing, app body limits, PostgreSQL-backed rate limiting and deployment harnesses. | PASS | MEDIUM | N/A. | NO IMPACT. | No change required. | Existing tests and harnesses in repo. | PASS |
| MCP-COMP-005 | Initialize must handle protocol version compatibility and capabilities truthfully. | APPLICABLE | Baseline route returns fixed protocol version; candidate patch reads initialize params and rejects unsupported versions. | FAIL | HIGH | Runtime does not demonstrate negotiated version handling on upstream baseline. | COMPATIBLE IMPACT. | AP-001. | Candidate `mcp.test.ts` case passed locally. | WAITING FOR SPECIFIC USER APPROVAL |
| MCP-COMP-006 | Tools must use `tools/list` and `tools/call` with stable names, schemas, descriptions and annotations. | APPLICABLE | One facade tool is catalog-enforced and returned with input/output schemas and annotations. | PASS | MEDIUM | N/A for current catalog model. | NO IMPACT. | No change required; expanding tool count would be catalog-impacting. | `mcp.test.ts`, registration and catalog tests. | PASS |
| MCP-COMP-007 | Input JSON Schema must be valid and server-side validation must still occur. | APPLICABLE | Registration compiles schemas; runtime validates input/output with AJV; manifest schema permits component-specific tool schemas. | PASS | MEDIUM | N/A. | NO IMPACT. | No change required. | Registration, catalog and MCP policy tests. | PASS |
| MCP-COMP-008 | Results must be structured, bounded, secret-safe and idempotent where needed. | APPLICABLE | `structuredContent`, text content, output validation, response limit and idempotency persistence. | PASS | MEDIUM | N/A. | NO IMPACT. | No change required. | MCP and policy tests. | PASS |
| MCP-COMP-009 | Agent autonomy must not bypass identity, scopes, route ACL, policy epoch or tool allowlist. | APPLICABLE | Component auth, managed-service auth and public MCP facade separation; no public agent loop exposed by `/mcp`. | PASS | MEDIUM | N/A for public MCP layer. | NO IMPACT. | No change required. | Existing component and managed-service authorization tests. | PASS |
| MCP-COMP-010 | Resources capability only if implemented. | APPLICABLE | Initialize capabilities declare only `tools`; no resources methods. | N/A | LOW | Product does not expose MCP Resources. | NO IMPACT. | No change required. | Static code/catalog evidence. | N/A WITH EVIDENCE |
| MCP-COMP-011 | Prompts capability only if implemented. | APPLICABLE | Initialize capabilities declare only `tools`; no prompts methods. | N/A | LOW | Product does not expose MCP Prompts. | NO IMPACT. | No change required. | Static code/catalog evidence. | N/A WITH EVIDENCE |
| MCP-COMP-012 | Protected MCP auth must satisfy relevant MCP Authorization Specification obligations. | APPLICABLE | Protected resource metadata and token/introspection endpoints exist; baseline AS metadata is underspecified for supported machine-client mode. | PARTIAL | HIGH | Discovery does not explicitly describe all implemented OAuth endpoints/capabilities. | COMPATIBLE IMPACT. | AP-005. | Candidate `auth-routes.test.ts` passed locally. | WAITING FOR SPECIFIC USER APPROVAL |
| MCP-COMP-013 | App-layer security must cover validation, authz, SSRF/path/SQL/command injection, prompt injection boundaries, limits and tenant relevance. | APPLICABLE | Zod/AJV validators, host/resource validation, parameterized DB queries, rate limits, secret redaction. | PASS | MEDIUM | N/A for audited paths. | NO IMPACT. | No change required. | Existing security and DB tests referenced by remediation matrix. | PASS |
| MCP-COMP-014 | Sensitive operations need confirmation in client/app/workflow. | APPLICABLE | Single facade tool exposes effect annotations; non-read operations require idempotency keys and per-credential authorization. | PASS | MEDIUM | Current catalog model delegates host-client approval UX through annotations. | NO IMPACT. | No change required; splitting sensitive tools would be catalog-impacting. | MCP, policy and permission tests. | PASS |
| MCP-COMP-015 | Errors need stable safe application code, retryable and correlation ID in JSON-RPC `error.data`. | APPLICABLE | Baseline exposes numeric JSON-RPC code, safe message and correlation id; candidate patch adds `code`, `retryable`, `correlation_id`. | FAIL | MEDIUM | Application error metadata is narrower than audit baseline. | COMPATIBLE IMPACT. | AP-004. | Candidate JSON-RPC tests passed locally. | WAITING FOR SPECIFIC USER APPROVAL |
| MCP-COMP-016 | Performance, timeout, state, restart, scaling and cancellation controls. | APPLICABLE | DB leases, rate buckets, timeouts, response limits and idempotency exist; candidate patch adds in-process cancellation. | PARTIAL | MEDIUM | Client cancellation was not wired to handler abort signals in upstream baseline. | COMPATIBLE IMPACT. | AP-003. | Candidate cancellation test passed locally. | WAITING FOR SPECIFIC USER APPROVAL |
| MCP-COMP-017 | Observability and audit must include structured logs, metrics, correlation ID, health/readiness, audit integrity and alerting. | APPLICABLE | MCP runtime logs, audit writes, invocation metrics, readiness, alerting and audit archive domains. | PASS | MEDIUM | N/A. | NO IMPACT. | No change required. | Existing audit/readiness/alert tests and release smoke evidence. | PASS |
| MCP-COMP-018 | ChatGPT Apps UI only if product declares interactive UI in ChatGPT. | APPLICABLE | No MCP Apps resources, widget metadata or Apps SDK implementation found. | N/A | LOW | Product does not currently declare a ChatGPT interactive UI. | NO IMPACT for N/A; COMPATIBLE IMPACT if added. | No change required. | Static code/catalog evidence. | N/A WITH EVIDENCE |
| MCP-COMP-019 | Metadata and names must be technical, true and traceable. | APPLICABLE | Persisted displayName/description/annotations and catalog capabilities. | PASS | LOW | N/A. | NO IMPACT. | No change required. | MCP and catalog tests. | PASS |
| MCP-COMP-020 | Versioning and backward compatibility must preserve or version public contracts. | APPLICABLE | Immutable catalogs and release constants pin `2025-11-25`. | PASS | MEDIUM | N/A for current immutable catalog versions. | NO IMPACT. | No change required. | Catalog checks. | PASS |
| MCP-COMP-021 | Required protocol, schema, security, operational, agent and OpenAI integration tests. | APPLICABLE | Internal tests exist; live OpenAI MCP Inspector/Responses/API Playground/ChatGPT evidence is absent. | PARTIAL | HIGH | External compatibility requires deployed endpoint and credentials. | COMPATIBLE IMPACT for local runtime test additions. | Add approved runtime tests; run external post-deploy tests later. | Candidate targeted tests passed; external tests not run. | WAITING FOR SPECIFIC USER APPROVAL and BLOCKED BY OBJECTIVE EXTERNAL BLOCKER |
| MCP-COMP-022 | Delivery docs must cover architecture, MCP layer, versions, auth, scopes, tools, schemas, errors, retry, deployment, rollback, autonomy and confirmations. | APPLICABLE | README, runbooks, requirements/remediation matrices and this forensic matrix. | FIXED | LOW | The requested MCP-COMP matrix did not exist in current docs. | NO IMPACT. | Add this document. | Markdown review and targeted local command evidence. | FIXED AND VERIFIED |
| MCP-COMP-023 | Acceptance state requires core protocol/security/OpenAI tests and catalog compatibility. | APPLICABLE | Local candidate tests passed; full CI, DB tests, deploy and OpenAI tests not run in this pass. | PARTIAL | HIGH | Approval gate and external endpoint requirements prevent complete remediation. | UNKNOWN IMPACT overall. | Obtain approval for AP-001 through AP-005, then run required verification. | Not complete. | WAITING FOR SPECIFIC USER APPROVAL |
| MCP-COMP-024 | MCP must stay an interoperable layer, not product architecture. | APPLICABLE | Separation across MCP HTTP route, domain auth/policy/registration and handlers. | PASS | LOW | N/A. | NO IMPACT. | No change required. | Static architecture evidence. | PASS |

## Approval packages

### AP-001: Initialize version compatibility handling

Current contract:

- `POST /mcp` `initialize` returns the release protocol version.
- Upstream baseline does not prove that `params.protocolVersion` is evaluated.
- Catalog and release constants pin `2025-11-25`.

Required contract:

- Preserve support for `2025-11-25`.
- Handle unsupported client versions with a safe standard JSON-RPC response or compatible version-selection behavior.
- Keep capabilities truthful as `{ tools: {} }`.

Touched files:

- `apps/server/src/http/mcp.ts`
- `apps/server/src/domain/release.ts`
- `scripts/generate-mcp-onboarding-catalog.mjs`
- `docs/onboarding-catalogs/component-2026.07.22.json`
- `apps/server/src/contracts/component-manifest-2026.07.22.schema.json`
- `apps/server/src/domain/registration.ts`
- `apps/server/src/http/mcp.test.ts`

Change class: `MINOR` if `2025-11-25` remains supported; `MAJOR` if existing clients break.

Risk: clients depending on the current fixed response or missing version handling may see new errors.

Migration: preserve `2025-11-25`, add protocol tests, avoid catalog digest edits unless a new catalog version is approved.

Rollback: revert runtime negotiation checks and associated tests.

Approval question: Approve implementing AP-001 as a backward-compatible `MINOR` runtime change that preserves cataloged MCP protocol version `2025-11-25`?

### AP-002: JSON-RPC notification HTTP status

Current contract:

- Upstream behavior expects notification requests such as `notifications/initialized` to return HTTP 204.
- MCP 2025-11-25 Streamable HTTP says accepted notification-only POST bodies return HTTP 202 with no body.

Required contract:

- Decide whether KCML public MCP notifications should move to 202 or retain the current 204 as a documented compatibility choice.

Touched files:

- `apps/server/src/http/json-rpc.ts`
- `apps/server/src/http/mcp.ts`
- `apps/server/src/http/mcp.test.ts`
- activation and release smoke paths if public behavior changes.

Change class: `PATCH` if only internal expectations are aligned; `MINOR` if public status changes.

Risk: public clients or tests relying on 204 may need adjustment.

Migration: document selected behavior and test both initialized notification and unknown notification behavior.

Rollback: restore prior 204 response behavior.

Approval question: Approve changing accepted MCP notification-only POST responses from 204 to 202 per MCP 2025-11-25 Streamable HTTP?

### AP-003: MCP cancellation

Current contract:

- Server-side timeout uses `AbortSignal`.
- Upstream baseline does not expose a request registry for `notifications/cancelled`.

Required contract:

- Best-effort handling of `notifications/cancelled` for matching in-flight requests without weakening timeout, idempotency or finalization guarantees.

Touched files:

- `apps/server/src/http/mcp.ts`
- `apps/server/src/domain/mcp-policy.ts`
- `apps/server/src/http/mcp.test.ts`

Change class: `MINOR`, potentially `MAJOR` if synchronous response semantics or idempotency finalization change.

Risk: request correlation, late completion and idempotency state can interact in subtle ways.

Migration: keep cancellation optional and preserve existing timeout behavior.

Rollback: remove cancellation registry and preserve server-side timeouts.

Approval question: Approve implementing AP-003 as optional best-effort MCP cancellation for matching in-flight requests in the current server process?

### AP-004: JSON-RPC error metadata

Current contract:

- JSON-RPC errors include numeric `error.code`, safe `message` and correlation id metadata.
- Stable application `code` and `retryable` are not uniformly exposed.

Required contract:

- Add stable safe application code and retryability in `error.data` while preserving the standard JSON-RPC envelope.

Touched files:

- `apps/server/src/http/json-rpc.ts`
- `apps/server/src/http/json-rpc.test.ts`
- `apps/server/src/http/mcp.test.ts`
- documentation if public error contract is documented.

Change class: `MINOR` if additive; `MAJOR` if existing metadata is renamed or removed.

Risk: clients parsing the current `correlationId` field may be affected if not preserved.

Migration: add new fields while retaining `correlationId` for a compatibility window.

Rollback: stop emitting additive fields.

Approval question: Approve implementing AP-004 as additive JSON-RPC error metadata with `code`, `retryable` and `correlation_id` while retaining `correlationId`?

### AP-005: OAuth authorization-server discovery metadata

Current contract:

- Authorization server metadata advertises `client_credentials` and `client_secret_basic`.
- Token endpoint supports pre-registered confidential machine clients.
- No Authorization Code, PKCE, Client ID Metadata Documents or Dynamic Client Registration flow is implemented.

Required contract:

- If the product supports only pre-registered machine clients for this catalog version, discovery must say that clearly and preserve client credentials.
- If user-facing public clients are in scope, add Authorization Code + PKCE with GUI-managed clients, redirect URIs, audit, RBAC, tests and docs.

Touched files:

- `apps/server/src/http/auth-routes.ts`
- `apps/server/src/domain/auth.ts`
- admin UI/API and migrations if a new user-client OAuth flow is approved.
- `apps/server/src/http/auth-routes.test.ts`

Change class: `MINOR` for additive metadata or additive user-client flow; `MAJOR` if existing machine clients break.

Risk: OAuth metadata and client registration are security-critical; adding user-client flow creates GUI-first storage requirements.

Migration: preserve existing client credentials indefinitely unless separately approved; add new GUI-managed config only with migration and tests.

Rollback: remove additive metadata or disable new grant types while preserving machine clients.

Approval question: Approve AP-005 as an additive metadata clarification for the existing pre-registered confidential machine-client OAuth mode, without adding Authorization Code + PKCE in this release?

## Verification performed in this pass

- `git status --short`: showed pre-existing uncommitted MCP/OAuth candidate changes and this document.
- `git fetch origin`: completed.
- `git rev-parse origin/main`: `35754cfa3668fe10af7e852dbaf9f7eac5de59ac`.
- `git log -1 --oneline origin/main`: `35754cf Merge pull request #53 from karelmartinek-a11y/audit/component-contract-forensics-20260719`.
- Read repository `AGENTS.md`, `README.md`, `package.json`, requirements matrix, remediation matrix, current MCP/OAuth/catalog source files, key tests and official MCP/OpenAI documentation.
- Targeted candidate tests: `corepack pnpm vitest run apps/server/src/http/auth-routes.test.ts apps/server/src/http/mcp.test.ts apps/server/src/http/json-rpc.test.ts apps/server/src/domain/mcp-policy.test.ts --exclude '**/._*'` passed: 4 test files, 32 tests.
- `corepack pnpm catalog:check`: passed.

Not run in this pass:

- `corepack pnpm install --frozen-lockfile`
- `corepack pnpm run ci`
- `corepack pnpm db:migrate`
- PostgreSQL integration suites with `KCML_TEST_DATABASE=1`
- CI, release, production deploy or post-deploy checks
- live OpenAI MCP Inspector, Responses API, API Playground or ChatGPT developer connection tests
- UI or visual checks, because no UI change was made

## GUI-first configuration and secrets assessment

The only completed `NO IMPACT` change in this pass is this audit document. It adds no runtime configuration, environment variable, secret, OAuth client, redirect URI, certificate, timeout or operational switch.

The candidate OAuth discovery metadata patch adds no new administrator-managed value. Any future Authorization Code + PKCE flow would require GUI controls, validation, localized help, authorized API, durable PostgreSQL storage, encrypted secret handling where applicable, masked readback, rotation/removal/revocation, audit records, RBAC, tests and documentation.

No `.env.example` change was made. No dependency change was made. No database migration was added. The deployment-only `PASS` exception was not changed or repurposed.

## Current status

Audit matrix created and corrected against the current prompt approval scope. Runtime remediation is partially blocked by required user approval for AP-001 through AP-005. Because approval is required before those catalog-impacting changes can be treated as implemented, this pass is:

`AUDIT COMPLETE - REMEDIATION PARTIALLY BLOCKED BY REQUIRED USER APPROVAL`
