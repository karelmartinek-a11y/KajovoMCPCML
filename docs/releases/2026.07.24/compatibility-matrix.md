# Compatibility Matrix 2026.07.24

| Path | Role | Compatibility |
| --- | --- | --- |
| `/v2/component-onboardings` | Native component intake | Requires blueprint component identity, release wave and token scope. |
| `/v2/component-onboardings/{id}/revisions` | Native revision intake | Requires `Idempotency-Key` and `If-Match`; returns `ETag`. |
| `/v2/component-mcp` | Native MCP component runtime | MCP `2025-11-25` streamable HTTP JSON-RPC; every initialize/list/call requires current audience-bound component token, route and scope permission. |
| `/v2/component-pulse`, `/v2/component-state-query` | Legacy native runtime adapters | Supported during migration; canonical new operations are `kcml.pulse.accept` and `kcml.state.push` through `/v2/component-mcp`. |
| External gateway | Component-to-external target | Canonical HTTPS target, pinned public DNS address with hostname TLS verification, audience-bound token, persistent circuit breaker and bounded retry. |
| `/v1/onboardings` | Legacy MCP adapter | Supported adapted path for historical MCP server onboarding. |
| `/v1/service-onboardings` | Legacy service adapter | Supported adapted path for external API and legacy service onboarding. |
| `/v1/integration-intent` | Token-scoped handoff discovery | Returns the recommended intake URL, native and legacy intake URLs, and the exact blueprint component scope granted to the token. |
| Secret API integration token principal | Release token grant | Uses integration token UUID/fingerprint as its own principal. |
| Secret API access token principal | Child component grant | Uses component UUID/access token as a separate principal. |
| FlowFabric first-wave blueprint | Dry-run-only AI/MCP component source snapshot | Cataloged as forensic evidence for 20 implementer child jobs; managed services remain platform prerequisites and no runtime identity is preassigned. |

The first release wave contains 9 AI, 11 MCP and 5 managed service blueprint components. That count is a versioned baseline, not a system ceiling.

Supported native component categories (`AI_AGENT`, `MCP_SERVER`, `KCML_MANAGED_SERVICE`, `GENERIC_COMPONENT`) use the same MCP runtime tool namespace. Historical 2026.07.23 manifests and v1 intake paths remain immutable and supported only through their documented adapters.
