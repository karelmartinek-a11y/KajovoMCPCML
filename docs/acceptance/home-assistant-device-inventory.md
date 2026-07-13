# Acceptance evidence: Home Assistant device inventory

This package belongs to registration revision
`ha-device-inventory-1.0.0`. Runtime results are stored in the latest
`registration_revision.evidence` record; the table below identifies the
evidence source that must be checked before a status is recorded as `PASS`.

| Evidence | Required proof |
| --- | --- |
| C-01–C-04 | Binding manifest validates, artifact and manifest digests are stored, handler key/version exist in the running registry, and registration starts disabled. |
| C-05–C-07 | Exact hostname/resource allocation is catalog-derived, OAuth audience is exact, and Kaja permission is scoped to the single server. |
| C-08–C-10 | Runbook, monitoring targets and rollback/decommission references are present and audit events are append-only. |
| T-01–T-03 | Real MCP `initialize`, `tools/list` and successful `tools/call`; the call returns the Markdown table and schema-valid structured content. |
| T-04–T-08 | Unknown tool/host, missing or wrong-audience token, and missing permission all fail closed. |
| T-09–T-15 | Revocation/disable, strict input and output schemas, timeout/size limits, redacted logs, statistics and restart persistence are verified. |
| T-16–T-20 | Admin workflow uses live catalog state, starts disabled, records the smoke result, requires evidence before activation, and retains audit history. |
| T-21–T-25 | CI, backup/rollback, health monitoring, documentation traceability, and one-host/one-tool isolation pass. |

No status may be promoted by assumption. The activation endpoint accepts only
the complete C-01…C-10 and T-01…T-25 matrix with every status equal to `PASS`.

