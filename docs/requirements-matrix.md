# KCML forensic compliance requirements matrix

Current contract: `2026.07.22-compliance.1`. Historical catalogs remain immutable only as migration inputs; they are not accepted for new component registration and are not runtime sources of truth.

| Requirement | Authoritative implementation | Durable evidence / fail-closed rule |
| --- | --- | --- |
| Generic managed object | `component`, `component_revision` and the generic component manifest | KCML assigns `KCML####` and `kcml####.kajovocml.hcasc.cz`; kind is informational and does not select behavior |
| Exactly two token classes | `integration_token`, `principal_access_token`, migrations `069`, `080`, `083`, `084` | integration token is exactly 24 hours and consumed only after successful handoff; access token is long-lived until rotation/revocation; component credentials and integration-token secret grants are retired |
| Request-time authorization | `domain/component-auth.ts` | every call rechecks digest, audience, Host, Client ID binding, issued scopes, live permission, lifecycle/quarantine state and policy/revocation epochs |
| Canonical MCP runtime | `http/mcp.ts`, `http/component-mcp-runtime.ts` | canonical `/mcp` lists 0..N declared tools, validates input/output, applies concurrency and dispatches via UDS or protected HTTPS egress |
| Operation observability | `component_operation_lease`, append-only audit chain | authorization, lease, dispatch, result/error and finalization are correlated and retain payload digests |
| Generic onboarding | `domain/component.ts`, `http/component-routes.ts`, generic schema/catalog | actual evidence bytes and fixtures are persisted; identity is server-assigned; client-supplied E2E output and legacy credential claims return 410 |
| Active readiness | `ACTIVATION_GATES` in `domain/component.ts` | all 38 gates require current revision/artifact evidence; missing declarations use explicit server-owned N/A evidence only where the capability is absent |
| Durable E2E | `onboarding/component-e2e-worker.ts` and service unit | KCML loads stored fixtures, invokes the production-shape route, compares exact output and records per-scenario results |
| Durable control | `onboarding/component-control-worker.ts` and service unit | leased outbox performs real UDS/HTTPS writes; enable/disable/state/heartbeat require ACK and observed state evidence |
| State and heartbeat | component state/heartbeat routes and domain functions | full snapshots require exact declared keys; invalid observations fail; push and challenge are independently evidenced |
| Monitoring | `onboarding/monitoring.ts`, `kcml-monitor.service` | canonical component health uses UDS or KCML egress; stale heartbeat and failed watchdog degrade/fail closed and alert |
| Secrets | `domain/secret-manager.ts`, `http/secret-api-routes.ts`, Secrets GUI | encrypted versioned storage, masked administration, grants and audit; runtime resolution accepts only a scoped long-lived access bearer |
| External communication | canonical principal/permission tables and protected egress | registered-to-registered, external inbound and external outbound use the same current-state authorization and operation evidence model |
| Deployment | release scripts, nginx and systemd units | immutable CI artifact; server, onboarding, monitor, control and E2E workers run separately with database-backed heartbeats |
| Compatibility | `docs/releases/2026.07.22-compliance.1/compatibility-matrix.md` | breaking catalog change is user-approved; historical artifacts are preserved; new intake uses only the generic catalog |

Verification results belong in the completion report and must be recorded only after the named command has actually run.
