# KCML compliance release 2026.07.22-compliance.1

This immutable release defines generic onboarding for any API-capable component. KCML assigns the component identity and canonical hostname, and exposes the component through `https://kcml####.kajovocml.hcasc.cz/mcp`.

The runtime recognizes exactly two token classes: a 24-hour reusable-until-success integration token and a long-lived access token that remains valid until rotation or revocation. Every runtime call is authorized against current principal, component, permission, route and scope state.

Activation requires all 38 active evidence gates for the same manifest revision and runtime artifact digest. Control and E2E workers use a GUI-rotatable platform access token stored encrypted in PostgreSQL and are required by production readiness.

Machine-readable artifacts:

- `docs/onboarding-catalogs/component-2026.07.22-compliance.1.json`
- `apps/server/src/contracts/component-manifest-2026.07.22-compliance.1.schema.json`
- `docs/onboarding-manifest-2026.07.22-compliance.1.example.json`

Rollback deploys the preceding immutable release. Database changes are forward-only and retained for a migration-compatible rollback.

During upgrade, a legacy component that is still marked active but lacks the complete current revision/runtime evidence set is preserved in the registry and moved fail-closed to `QUARANTINED/BLOCKED`. Its communication directions and runtime target are disabled, authorization epochs advance, credentials are revoked, and an alert plus audit event are recorded. Restoration requires explicit recertification against the current 38-gate contract; rollback does not fabricate evidence or reactivate the component.
