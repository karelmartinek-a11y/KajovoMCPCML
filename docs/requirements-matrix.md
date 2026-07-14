# KCML SSOT v1.6 Requirements Matrix

Legacy production revision 1.4 remains immutable and readable until recertification. Every new intake or change is strict against the published JSON catalogs for MCP `1.6` and `EXTERNAL_API` `1.0`, with machine-readable receipts and fail-closed runtime gates.

| Requirement | Implementation | Persisted evidence | Automated gate |
| --- | --- | --- | --- |
| Strict registration | `domain/registration.ts`, `domain/external-api.ts`, published onboarding catalogs | canonical manifest/schema digests, evidence references, owners, dependencies, approvals and machine-readable gate receipts | unknown/missing fields, drift, unsafe defaults and missing evidence fail before KCML allocation |
| One token / job / server | onboarding transaction and unique bindings | integration token descriptor, fingerprint, job and KCML identity | concurrent idempotency and binding tests |
| Integration token UX | descriptor modal and handoff | full token is permitted in authenticated create response, UI and handoff; database/audit retain digest and fingerprint | descriptor API/UI tests; `note` and `unspecified` rejected |
| State machine | `domain/server-state.ts` | transition event, reason, actor and correlation ID | invalid transition and direct active-profile edit tests |
| Managed service control plane | `domain/managed-service.ts`, admin service routes, `managed_service*` tables | lifecycle state, operational state, `api_state`, disable reason, active revision and revocation epochs | disable/enable transitions, state reads, log reads and permission churn tests |
| Recertification | shared evaluator in activation, auth, MCP, discovery and monitor | normalized approval/due dates, interval, validation state and warning timestamp | exact VALID/WARNING/GRACE/SUSPENDED/INVALID boundary tests |
| Resource authorization | HMAC access tokens and request-time authorizer | one audience/service/credential binding, scope set, permission epoch, active revision epoch and recertification evidence | missing revision/profile, wrong audience, grace/suspend, immediate revocation and stale-monitoring tests |
| External API gateway enforcement | controlled egress proxy plus `EXTERNAL_API` runtime matcher | templated path/method/operation binding, correlation ID, gate receipts, egress capability and redacted runtime logs | direct bypass, wrong scope, wrong route, disable existing token and gateway header enforcement tests |
| Discovery privacy | fail-closed MCP discovery | active revision and profile reference | unavailable states expose no catalog detail |
| Shared HTTP throttling | `@fastify/rate-limit` with a fail-closed PostgreSQL store and HMAC bucket keys | route/IP bucket counters without raw client identifiers | 100 concurrent increments serialize exactly; sensitive routes carry explicit limits |
| Database migrations | checksum ledger and advisory-locked runner | canonical 001-021 ledger plus hashed archive of superseded pre-ledger 007-014; 017-021 cover managed services, backfill, shared HTTP throttling and `EXTERNAL_API` runtime enforcement | clean, production-ledger upgrade, idempotency, changed/late migration rejection |
| Tamper-evident audit | database append function, serialized `audit_head` | complete previous/event hash chain and verification result | 100 concurrent writes without branches plus tamper detection |
| Invocation integrity | accepted/final transaction model | request/response digests, status, latency, statistics and linked audit | pre-audit failure blocks handler; finalization failure opens Critical alert without handler retry |
| Monitoring | separate `kcml-monitor.service` plus managed-service probe persistence | per-probe samples, freshness, SLO, state history, scheduler heartbeat, deduplicated alerts and recovery events | one bad server cannot stop other probes or onboarding; stale or failed `EXTERNAL_API` probes fail closed |
| Alert delivery | dual HMAC-signed HTTPS dispatcher | idempotency key, attempts, status, response digest, retry and dead letter | signature and lifecycle tests; UI suppression expiry audit |
| Runtime isolation | rootless Podman supervisor and egress proxy | image/source/build/provenance/SBOM digests | timeout, secret/path policy, egress and drift tests |
| Keyless supply chain | GitHub OIDC and Cosign identity policy | immutable image digest and attestation | exact issuer/repository/workflow mismatch fails closed |
| Admin security | deployment-managed `karmar78`, session/CSRF/MFA | login/recovery/security events | no public bootstrap route; password sync only through `PASS` |
| Least privilege | owner/migrator and `kcml_app` roles; per-service credentials | grants and credential-file inventory | application cannot mutate audit rows/head or run migrations |
| Immutable delivery | CI-built release, SBOM, checksum and keyless Sigstore bundle | release manifest/build ID plus GitHub OIDC certificate and transparency proof | production verifies repository/workflow/ref/SHA/trigger and does not build or download dependencies |
| Recovery | encrypted `age` backup and isolated restore test | checksum and restore evidence | backup mode/recipient/preflight and quarterly restore gate |
| A22 soak readiness | `scripts/external-api-soak.mjs` and release runbook | JSONL trace, summary JSON, permission churn/disable-enable evidence and implementation status | harness is release-ready and reports `PARTIALLY_IMPLEMENTED` until a full 72-hour run completes |
| UI operations | token modal, permissions page and monitoring workspace | recertification phase, block reason, alerts, probe age, history and deliveries | Playwright desktop/mobile workflows and empty states |
