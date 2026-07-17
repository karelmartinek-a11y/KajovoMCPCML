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
2. A push to `main` or manual `workflow_dispatch` on `main` assembles the production release and drives deployment. Pull requests never deploy.
3. CI emits an SBOM, release checksum and transparency-logged keyless Sigstore bundle issued from GitHub OIDC.
4. The deploy job uses the `production` environment and its sole `PASS` secret. Workflow conditions require `refs/heads/main` and allow only `push` or explicit `workflow_dispatch`.
5. The dedicated runner verifies the checksum. The sudo wrapper verifies the Sigstore bundle's issuer, workflow identity, repository, `main` ref, exact commit SHA and exact GitHub trigger (`push` or `workflow_dispatch`) before extraction, then checks the immutable release manifest.

## Server install order

`install-release.sh` performs the following fail-closed sequence:

1. Install nginx and systemd definitions, including the separate `kcml-monitor.service`.
   Legacy installations missing explicit control-plane host variables derive `admin`, `auth` and `register` hostnames from `PUBLIC_BASE_DOMAIN`; explicitly configured custom hostnames remain unchanged.
2. Materialize per-service environment and credential files with modes `0700/0600`.
3. Run preflight for TLS SAN, rootless Podman, Cosign identity, two separately keyed signed HTTPS alert sinks, `age`, service credentials and writable isolated paths.
4. Create an encrypted custom-format PostgreSQL backup plus checksum.
5. Apply checksum-locked forward migrations under advisory lock and timeouts.
6. Create/update the non-owner `kcml_app` role through local PostgreSQL administration and revoke direct audit-table mutation.
7. Synchronize only the deployment-managed bootstrap admin password from `PASS` and the server-held MFA secret.
8. Snapshot the prior nginx/systemd process contract, atomically switch `/opt/kcml/current`, and start web, onboarding, monitor, egress and both alert sinks.
9. Require all services active, both signed webhook deliveries confirmed, admin login from `PASS`, OAuth metadata, unknown-host rejection, KCML0002 discovery, egress socket, audit chain, the complete migration ledger through `036`, and KCML0002 `ACTIVE/HEALTHY`.

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
