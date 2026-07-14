# KCML SSOT v1.5 Requirements Matrix

Legacy production revision 1.4 remains immutable and readable until recertification. Every new intake or change is strict manifest 1.5.

| Requirement | Implementation | Persisted evidence | Automated gate |
| --- | --- | --- | --- |
| Strict registration 1.5 | `domain/registration.ts`, upload validation | canonical manifest/schema digests, evidence references, owners, dependencies, approvals | unknown/missing fields, drift, unsafe defaults and missing evidence fail before KCML allocation |
| One token / job / server | onboarding transaction and unique bindings | integration token descriptor, fingerprint, job and KCML identity | concurrent idempotency and binding tests |
| Integration token UX | descriptor modal and handoff | full token is permitted in authenticated create response, UI and handoff; database/audit retain digest and fingerprint | descriptor API/UI tests; `note` and `unspecified` rejected |
| State machine | `domain/server-state.ts` | transition event, reason, actor and correlation ID | invalid transition and direct active-profile edit tests |
| Recertification | shared evaluator in activation, auth, MCP, discovery and monitor | normalized approval/due dates, interval, validation state and warning timestamp | exact VALID/WARNING/GRACE/SUSPENDED/INVALID boundary tests |
| Resource authorization | HMAC access tokens and permission service | one audience/server/credential binding and revocation epochs | missing revision/profile, wrong audience, grace/suspend and immediate revocation tests |
| Discovery privacy | fail-closed MCP discovery | active revision and profile reference | unavailable states expose no catalog detail |
| Shared HTTP throttling | `@fastify/rate-limit` with a fail-closed PostgreSQL store and HMAC bucket keys | route/IP bucket counters without raw client identifiers | 100 concurrent increments serialize exactly; sensitive routes carry explicit limits |
| Database migrations | checksum ledger and advisory-locked runner | canonical 001-019 ledger plus hashed archive of superseded pre-ledger 007-014; 017-018 add only the compatibility managed-service model and backfill, 019 adds shared HTTP throttling | clean, production-ledger upgrade, idempotency, changed/late migration rejection |
| Tamper-evident audit | database append function, serialized `audit_head` | complete previous/event hash chain and verification result | 100 concurrent writes without branches plus tamper detection |
| Invocation integrity | accepted/final transaction model | request/response digests, status, latency, statistics and linked audit | pre-audit failure blocks handler; finalization failure opens Critical alert without handler retry |
| Monitoring | separate `kcml-monitor.service` | per-probe samples, freshness, SLO, state history and scheduler heartbeat | one bad server cannot stop other probes or onboarding |
| Alert delivery | dual HMAC-signed HTTPS dispatcher | idempotency key, attempts, status, response digest, retry and dead letter | signature and lifecycle tests; UI suppression expiry audit |
| Runtime isolation | rootless Podman supervisor and egress proxy | image/source/build/provenance/SBOM digests | timeout, secret/path policy, egress and drift tests |
| Keyless supply chain | GitHub OIDC and Cosign identity policy | immutable image digest and attestation | exact issuer/repository/workflow mismatch fails closed |
| Admin security | deployment-managed `karmar78`, session/CSRF/MFA | login/recovery/security events | no public bootstrap route; password sync only through `PASS` |
| Least privilege | owner/migrator and `kcml_app` roles; per-service credentials | grants and credential-file inventory | application cannot mutate audit rows/head or run migrations |
| Immutable delivery | CI-built release, SBOM, checksum and GitHub attestation | release manifest/build ID | production does not build or download dependencies |
| Recovery | encrypted `age` backup and isolated restore test | checksum and restore evidence | backup mode/recipient/preflight and quarterly restore gate |
| UI operations | token modal, permissions page and monitoring workspace | recertification phase, block reason, alerts, probe age, history and deliveries | Playwright desktop/mobile workflows and empty states |
