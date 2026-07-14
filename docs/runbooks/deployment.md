# Production Deployment Runbook

## Trust model

- The only manually managed GitHub secret is the protected `production` environment secret `PASS` for the deployment-managed `karmar78` account.
- GitHub's automatic `GITHUB_TOKEN` is used only to download and verify the release attestation.
- Database, HMAC, MFA, GitHub App and alert-webhook credentials remain on the server. `split-service-config.sh` exposes only the credentials required by each service through systemd `LoadCredential`.
- Handler images use keyless Cosign verification bound to the exact GitHub OIDC issuer, repository, workflow and `main` identity.
- The `kcml-deploy` runner is unprivileged. Its only sudo grants are the root-owned release and bounded GHCR preload wrappers.

## Release gate

1. Pull-request CI runs lint, typecheck, unit/integration tests, clean migrations, a production-shape upgrade, database-role isolation, dependency audit, secret scan, CodeQL and build.
2. A manual `workflow_dispatch` on `main` assembles the already-built production release. A push or pull request cannot deploy; this is the compensating approval control for private repositories whose GitHub plan does not expose environment reviewers.
3. CI emits an SBOM, release checksum and GitHub OIDC build-provenance attestation.
4. The deploy job uses the `production` environment and its sole `PASS` secret. Workflow conditions require `refs/heads/main` and an explicit manual dispatch.
5. The dedicated runner verifies the checksum. The sudo wrapper verifies the GitHub attestation, source repository and immutable release manifest before extraction.

## Server install order

`install-release.sh` performs the following fail-closed sequence:

1. Install nginx and systemd definitions, including the separate `kcml-monitor.service`.
2. Materialize per-service environment and credential files with modes `0700/0600`.
3. Run preflight for TLS SAN, rootless Podman, Cosign identity, two separately keyed signed HTTPS alert sinks, `age`, service credentials and writable isolated paths.
4. Create an encrypted custom-format PostgreSQL backup plus checksum.
5. Apply checksum-locked forward migrations under advisory lock and timeouts.
6. Create/update the non-owner `kcml_app` role through local PostgreSQL administration and revoke direct audit-table mutation.
7. Synchronize only the `karmar78` password from `PASS` and the server-held MFA secret.
8. Snapshot the prior nginx/systemd process contract, atomically switch `/opt/kcml/current`, and start web, onboarding, monitor, egress and both alert sinks.
9. Require all services active, both signed webhook deliveries confirmed, admin login from `PASS`, OAuth metadata, unknown-host rejection, KCML0002 discovery, egress socket, audit chain, migration 019 and KCML0002 `ACTIVE/HEALTHY`.

## Backup and restore evidence

- `/opt/kcml/backups` is mode `0700`; files are mode `0600`.
- `backup.sh` encrypts every new dump to the server's `age` recipient before persistence and applies retention cleanup.
- `restore-test.sh` verifies the checksum, restores into an isolated temporary database and validates the audit chain.
- A restore test is required quarterly and before a risky database change.

## Rollback

Run `deploy/scripts/rollback.sh <release-id>`. Rollback is allowed only to a migration-compatible release. The script restores the versioned nginx/systemd snapshot together with the immutable release symlink; database history, audit events, KCML identities and revocation epochs are never reset.
