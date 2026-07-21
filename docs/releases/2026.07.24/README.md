# KajovoCML release 2026.07.24

This release defines the first production release wave baseline for native component onboarding.

- Baseline wave: `baseline-2026-07-24`.
- Scope: 9 AI agents, 11 MCP servers and 5 KCML managed services.
- FlowFabric source: `docs/blueprints/flowfabric-first-wave-2026.07.24.json` records the forensic snapshot from KajovoFlowFabric commit `937fba4de2716586350ad6a1ac8dd52b9848c96a`.
- FlowFabric readiness: `READY_FOR_DRY_RUN_ONLY`; the catalog records validated dry-run artifacts and blockers, but runtime identities, credentials, hostnames and final tool names are still assigned only by KájovoCML onboarding.
- The baseline wave is not the final target scope. Future waves may add more components without changing the compatibility role of this release.
- Legacy v1 onboarding remains available as an explicit compatibility adapter.
- Native v2 component intake is fail-closed against blueprint identity, release wave, token scope, duplicate child components, child-job limits and revision concurrency headers.
- Blueprint release token handoff recommends `/v2/component-onboardings` and still includes `/v1/service-onboardings` only as a legacy service adapter.
- Component runtime operations use MCP `2025-11-25` at `/v2/component-mcp`; legacy v2 operation paths remain compatibility adapters.
- Migrations `051`-`057` are forward-only. Recovery uses the migration-compatible previous application release while retaining added nullable tables/columns; do not reverse or manually delete audit, token, gateway-call or circuit state.
- External target disable/revoke is the immediate operational rollback for outbound gateway changes. It prevents new dispatch before DNS or network I/O while preserving the audit trail.
