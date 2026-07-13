# KCML SSOT Requirements Matrix

This matrix maps the SSOT v1.3 requirements to implemented components and
evidence locations.

| Requirement area | Component | Database object | API/UI | Security measure | Automated test | Acceptance evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Host isolation | Host Router, MCP routes | `mcp_server.hostname` unique | `kcmlNNNN.hcasc.cz/mcp` | exact hostname lookup before metadata/handler | `host-routing.test.ts` | unknown hosts return 404 without catalog leak |
| Token entropy | `security/secrets.ts` | `kaja_credential`, `access_token` | Kaja create, OAuth token | 64 CSPRNG bytes; no UUID secrets | `secrets.test.ts` | Base64URL token decodes to at least 64 bytes |
| Secret storage | Auth domain | `secret_hash`, `lookup_digest` | one-time UI display | Argon2id, HMAC digest, fingerprint only | `secrets.test.ts` | no full token column exists |
| OAuth authority | Auth routes | `kaja_credential`, `kaja_permission` | `/oauth/token` | `client_secret_basic`, resource audience | `auth-contract.test.ts` | token requires active Kaja, permission, active server |
| MCP protocol | MCP routes | `mcp_server` | `/mcp` | bearer only, exact audience | `mcp-contract.test.ts` | initialize/tools/list/tools/call supported |
| Registration gate | Registration domain | `registration_revision` | manifest validator | strict schema, no unknown fields | `registration.test.ts` | invalid manifest rejected |
| Admin login | Admin routes | `admin_account`, `admin_session` | `/api/login` | PASS sync, Argon2id, MFA, HttpOnly session, CSRF | `admin-security.test.ts` | login inactive without MFA |
| Audit | Audit writer | `audit_event` | audit table | append-only trigger, redaction | `audit.test.ts` | update/delete rejected |
| Monitoring | Admin UI + health | `function_statistics`, state fields | `/health`, dashboard | no healthy without DB readiness | `health.test.ts` | readiness returns 503 on DB failure |
| Deployment | GitHub Actions + deploy scripts | migration table | systemd/compose | masked `PASS`, preflight, backup, rollback | CI workflow | CI blocks deploy on failed tests |
| Nultá verze | Seed migration | empty `mcp_server` | dashboard | no demo KCML entries | `zero-state.test.ts` | clean DB catalog is empty |
| Home Assistant inventory | `home_assistant_device_inventory@1.0.0` | catalog-assigned `mcp_server` + registration evidence | one-tool MCP resource and registration workflow | loopback-only upstream; HA token remains in agent; strict empty input and bounded output | `home-assistant-device-inventory.test.ts`, agent `test_device_inventory.py` | `docs/acceptance/home-assistant-device-inventory.md`, real MCP call and C-01…C-10/T-01…T-25 matrix |
