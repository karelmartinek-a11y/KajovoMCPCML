# Production Deployment Runbook

## Trust model

- The only manually managed GitHub secret is the protected `production` environment secret `PASS` for the deployment-managed bootstrap admin account defined by `ADMIN_BOOTSTRAP_USERNAME`.
- GitHub's automatic `GITHUB_TOKEN` is used only by standard artifact transfer actions; release trust comes from a keyless Sigstore bundle issued from GitHub OIDC.
- Database, HMAC, MFA, GitHub App and alert-webhook credentials remain on the server. `split-service-config.sh` exposes only the credentials required by each service through systemd `LoadCredential`.
- Handler images use keyless Cosign verification bound to the exact GitHub OIDC issuer, repository, workflow and `main` identity.
- The `kcml-deploy` runner is unprivileged. Its only sudo grants are the root-owned release and bounded GHCR preload wrappers.
- The GHCR preload wrapper reads only the worker database credential from `/etc/kcml/credentials/worker/database_url`; it does not reload the legacy aggregate environment file.

## Release gate

1. Pull-request CI runs lint, typecheck, unit/integration tests, clean migrations, a production-shape upgrade, database-role isolation, dependency audit, secret scan, CodeQL and build.
2. A push to `main` or manual `workflow_dispatch` on `main` assembles the production release and drives deployment. Pull requests never deploy. Production deploy jobs share one non-cancelling concurrency group, so a privileged install already in progress is never interrupted.
3. CI emits an SBOM, release checksum and transparency-logged keyless Sigstore bundle issued from GitHub OIDC.
4. The deploy job uses the `production` environment and its sole `PASS` secret. Workflow conditions require `refs/heads/main` and allow only `push` or explicit `workflow_dispatch`.
5. After acquiring the production concurrency lock, the dedicated runner compares the run SHA with the current `main` ref through the authenticated GitHub API. A stale run skips every artifact and deployment step. The latest run verifies the checksum, and the sudo wrapper verifies the Sigstore bundle's issuer, workflow identity, repository, `main` ref, exact commit SHA and exact GitHub trigger (`push` or `workflow_dispatch`) before extraction, then checks the immutable release manifest.

## Server install order

`install-release.sh` performs the following fail-closed sequence:

1. Install nginx and systemd definitions, including the separate `kcml-monitor.service` and the Secret API virtual host `secrets.<PUBLIC_BASE_DOMAIN>`.
   Legacy installations missing explicit control-plane host variables derive `admin`, `auth`, `register` and `secrets` hostnames from `PUBLIC_BASE_DOMAIN`; explicitly configured custom hostnames remain unchanged.
2. Materialize per-service environment and credential files with modes `0700/0600`.
3. Run preflight for TLS SAN including `secrets.<PUBLIC_BASE_DOMAIN>`, rootless Podman, Cosign identity, two separately keyed signed HTTPS alert sinks, `age`, service credentials and writable isolated paths.
4. Create an encrypted custom-format PostgreSQL backup plus checksum.
5. Apply checksum-locked forward migrations under advisory lock and timeouts.
6. Create/update the non-owner `kcml_app` role through local PostgreSQL administration and revoke direct audit-table mutation.
7. Synchronize only the deployment-managed bootstrap admin password from `PASS` and the server-held MFA secret.
8. Snapshot the prior nginx/systemd process contract, atomically switch `/opt/kcml/current`, and start web, onboarding, canonical component control, canonical component E2E, monitor, egress and both alert sinks.
9. Require all services and database-backed worker heartbeats current, both signed webhook deliveries confirmed, admin login from `PASS`, OAuth and Secret API metadata, unknown-host rejection, egress socket, audit chain, the complete checksummed migration ledger, the two-token invariants and canonical identity consistency. If components exist, probe the first assigned hostname dynamically; no component is privileged by deployment code.

## Secret Manager Operations

- Secret values are authoritative in PostgreSQL and manageable through the KCML admin Secrets page. Do not add application `.env` keys or GitHub Actions secrets for managed values.
- Encryption uses the existing `CONFIG_VAULT_MASTER_KEY_BASE64` and `CONFIG_VAULT_MASTER_KEY_ID`; rotating that bootstrap key requires the normal config-vault key-rotation procedure and a Secret Manager re-encryption migration plan.
- Runtime clients call `POST https://secrets.<PUBLIC_BASE_DOMAIN>/v1/secrets/resolve` only with the component's long-lived KCML access bearer and the `secret.resolve` scope.
- Every resolve rechecks the current principal and component lifecycle, activation, egress, policy epoch and revocation epoch. It then requires an active secret plus a current explicit or all-secrets grant. Integration tokens and retired component client secrets are never runtime secret identities; missing, inactive, deleted and ungranted names remain indistinguishable as `secret_unavailable`.

## Backup and restore evidence

- `/opt/kcml/backups` is mode `0700`; files are mode `0600`.
- `backup.sh` encrypts every new dump to the server's `age` recipient before persistence and applies retention cleanup.
- `restore-test.sh` verifies the checksum, restores into an isolated temporary database and validates the audit chain.
- A restore test is required quarterly and before a risky database change.

## Factory reset after testing

Use this only with the owner/migrator database credential after the normal encrypted backup has completed. The reset archives every public runtime table under the owner-only `factory_reset_archive` schema, truncates runtime data including administrators, sessions, credentials, tokens, servers, monitoring history and the active audit chain, then initializes an empty audit head. Migration state and operational configuration remain in place, so the next admin visit starts the one-time OWNER bootstrap without rerunning schema migrations.

```bash
KCML_PROCESS_ROLE=migrate \
KCML_FACTORY_RESET_CONFIRM=ARCHIVE_AND_RESET_KCML \
DATABASE_URL='postgresql://…' \
node apps/server/dist/cli/factory-reset.js
```

The command is transactional and refuses to start without the exact confirmation value. Keep the reported reset run ID with the encrypted pre-reset backup. Archived rows are deliberately outside the normal application schema and must not be granted to `kcml_app`.

## Rollback

Run `deploy/scripts/rollback.sh <release-id>`. Rollback is allowed only to a migration-compatible release. The script restores the versioned nginx/systemd snapshot together with the immutable release symlink; database history, audit events, KCML identities and revocation epochs are never reset.
