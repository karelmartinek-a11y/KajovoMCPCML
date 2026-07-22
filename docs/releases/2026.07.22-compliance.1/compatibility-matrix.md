# Compatibility matrix 2026.07.22-compliance.1

| Element | UDS runtime | HTTPS runtime | Canonical MCP | KCML authorization/audit/monitoring |
| --- | --- | --- | --- | --- |
| Any API-capable component | Supported | Supported with pinned TLS identity | Required when MCP capabilities are declared | Required |
| Registered component calling another registered component | Supported through KCML gateway | Supported through KCML gateway | Supported | Required |
| External principal calling a registered component | Not applicable | Supported through canonical hostname | Supported | Required |
| Registered component calling an approved external target | Not applicable | Supported through KCML egress gateway | Not required for the external target | Required |

Compatibility classification: breaking catalog revision. Existing immutable catalogs remain available for audit and rollback, but all new registrations use the generic manifest and must pass the complete active-evidence gate set.
