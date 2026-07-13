# Home Assistant device inventory

## Purpose and data flow

`KCML0001` exposes one read-only MCP tool,
`get_home_assistant_device_inventory`. The central KCML `/mcp` route validates
the exact hostname, OAuth bearer token, Kaja permission, tool name, input
schema and output schema. Its handler calls only the loopback endpoint
`http://127.0.0.1:8103/internal/device-inventory` of the Home Assistant agent.
The Home Assistant long-lived token remains in the agent environment and is
never copied into KCML, the catalog, an MCP response or an audit event.

The response contains ten Czech table columns, summary counters, structured
rows and `markdown_table`. It is a point-in-time snapshot of the Home Assistant
device/entity registries, current states, available services and configuration.

## Contract and limits

- Effect class: `READ_ONLY`; no Home Assistant service is called.
- Input: an empty JSON object; additional properties are rejected.
- Upstream timeout: 15 seconds.
- Maximum response size: 2 MiB.
- Rate limit declared by the registration: 10 requests per 60 seconds.
- Concurrency declared by the registration: 2.
- Failure policy: fail closed with a generic MCP handler error; no partial or
  stale table is substituted.

## Operations

1. Check `systemctl status home-assistant-agent kcml`.
2. Check `curl -fsS http://127.0.0.1:8103/health` locally on the host.
3. Review structured logs with `journalctl -u kcml -u home-assistant-agent`.
   Correlate MCP requests using `correlationId`; do not paste credentials into
   diagnostic commands or tickets.
4. Confirm the catalog entry is `ACTIVE` or `TRIAL`, `enabled=true`, and its
   handler is `home_assistant_device_inventory@1.0.0`.
5. If Home Assistant returns no devices unexpectedly, verify registry access
   over its authenticated WebSocket API and validate the agent token in place.

## Rollback

Disable the catalog entry first so the public resource fails closed. Restore
the previous KCML and Home Assistant agent artifacts using the normal deployment
rollback procedure, restart both services and verify their health endpoints.
Do not reuse or export the Home Assistant token during rollback.

## Decommission

Revoke Kaja permissions for the resource, disable the server, rotate the
resource revocation epoch, retain the audit/evidence record, then set its
registration state to `RETIRED`. Remove the handler only after no active or
trial catalog entry references it. Remove the loopback endpoint in a separate
Home Assistant agent change after the MCP dependency has been retired.

