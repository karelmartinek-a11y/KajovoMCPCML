# Forensic reconstruction remediation matrix

Baseline request: audit commit `2d6cd9a29e9a26922ff94a83cd91adaa1ab4c714` or newer. Implementation branch: `codex/kcml-forensic-compliance`. Onboarding/catalog impact was explicitly approved by the user, including the generic onboarding catalog.

This matrix is traceability, not proof by assertion. Executable code, forward migrations, generated contracts and inspected test output remain authoritative.

| Area | Implemented invariant | Primary evidence |
| --- | --- | --- |
| Registry convergence | `component` is the canonical runtime/readiness/monitoring object; legacy records require a component binding and cannot be orphaned | migrations `068`–`087`, component DB compatibility and upgrade tests |
| Identity | server assigns sequential code and one canonical hostname; runtime rejects alternate Host/audience | generic manifest validator, component routes and MCP tests |
| Token lifecycle | only 24-hour reusable-until-success integration tokens and long-lived access tokens are operational for components | migrations `069`, `080`, `083`, `084`; onboarding and auth DB tests |
| Live authorization | scope carried by the token and current route permission are both required; state/epoch changes take effect immediately | `component-auth.ts`, active negative-auth readiness probes |
| Runtime | one component-backed `/mcp`; no `/v2/component-mcp` business runtime; all declared tools are contract validated and physically dispatched | canonical MCP implementation and UDS integration tests |
| Transport security | UDS boundary or HTTPS through the egress proxy with TLS identity, allowlist, timeout, payload and redirect controls | runtime, control, E2E and monitoring transports |
| Control plane | durable leasing worker; network write precedes SENT; enable requires ACK/state/heartbeat and disable remains blocked until confirmed | control worker implementation, attempts ledger and worker tests |
| E2E | expected output stays in KCML; worker invokes production-shaped endpoints and performs exact canonical/byte comparison | E2E worker, fixtures/runs/results tables and tests |
| State/liveness | exact full snapshot, schema/transition enforcement, push heartbeat and KCML challenge, stale fail-closed scheduler | state/heartbeat routes, component domain and monitor |
| Secrets | access-token-only runtime resolve, current scopes/state, encrypted storage, revocable GUI grants; integration tokens cannot receive grants | migration `084`, secret API/domain/UI and crypto tests |
| Audit | hash-chain integrity plus per-operation authorization, lease, dispatch and final result evidence | audit functions, operation ledger and readiness integrity gates |
| Readiness | 38 named active gates tied to revision, runtime/artifact digest, correlation, variant and expiry | `ACTIVATION_GATES`, readiness evaluator and gate-evidence table |
| Upgrade fail-closed reconciliation | pre-existing active components without complete current evidence cannot block deployment while remaining exposed | migration `087` quarantines them, disables every communication direction/runtime target, advances epochs, revokes credentials and records an alert plus hash-chain audit event |
| Delivery | generic production smoke, no preferred component, separate worker services and immutable release artifact | install/build scripts and systemd units |

Final verification status is intentionally not stated here; it is populated from the concrete CI, database, release and production runs in the completion report.
