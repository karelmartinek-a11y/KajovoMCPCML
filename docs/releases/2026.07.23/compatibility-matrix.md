# Compatibility Matrix 2026.07.23

| Path | Role | Compatibility |
| --- | --- | --- |
| `/v2/component-onboardings` | Native component intake | Requires blueprint component identity, release wave and token scope. |
| `/v2/component-onboardings/{id}/revisions` | Native revision intake | Requires `Idempotency-Key` and `If-Match`; returns `ETag`. |
| `/v1/onboardings` | Legacy MCP adapter | Supported adapted path for historical MCP server onboarding. |
| `/v1/service-onboardings` | Legacy service adapter | Supported adapted path for external API and legacy service onboarding. |
| Secret API integration token principal | Release token grant | Uses integration token UUID/fingerprint as its own principal. |
| Secret API component credential principal | Child component grant | Uses component UUID/client credential as a separate principal. |

The first release wave contains 9 AI, 11 MCP and 5 managed service blueprint components. That count is a versioned baseline, not a system ceiling.
