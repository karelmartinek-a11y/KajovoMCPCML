# KajovoCML release 2026.07.23

This release defines the first production release wave baseline for native component onboarding.

- Baseline wave: `baseline-2026-07-23`.
- Scope: 9 AI agents, 11 MCP servers and 5 KCML managed services.
- FlowFabric source: `docs/blueprints/flowfabric-first-wave-2026.07.23.json` records the forensic snapshot from KajovoFlowFabric commit `937fba4de2716586350ad6a1ac8dd52b9848c96a`.
- FlowFabric readiness: `READY_FOR_DRY_RUN_ONLY`; the catalog records validated dry-run artifacts and blockers, but runtime identities, credentials, hostnames and final tool names are still assigned only by KájovoCML onboarding.
- The baseline wave is not the final target scope. Future waves may add more components without changing the compatibility role of this release.
- Legacy v1 onboarding remains available as an explicit compatibility adapter.
- Native v2 component intake is fail-closed against blueprint identity, release wave, token scope, duplicate child components, child-job limits and revision concurrency headers.
- Blueprint release token handoff recommends `/v2/component-onboardings` and still includes `/v1/service-onboardings` only as a legacy service adapter.
