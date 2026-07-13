# Deployment Runbook

## Required secrets

- GitHub secret `PASS`: production password for admin account `karmar78`.
- Server-side `/etc/kcml/kcml.env`: `DATABASE_URL`, purpose-separated access/integration/egress HMAC keys, session/CSRF/MFA keys, host names, GitHub API authorization (existing repository token or GitHub App), GHCR namespace and trusted signing-key path.

`PASS` is never echoed. If `PASS` is missing or empty, deployment fails closed.
Operational secrets are generated and retained
on the production server, not stored in GitHub Secrets.

## Order

1. Build and test in CI.
2. Deploy job runs on the production self-hosted runner.
3. Load `/etc/kcml/kcml.env`.
4. Run `deploy/scripts/preflight.sh`. It blocks release without the DNS-01 wildcard certificate SAN for `*.hcasc.cz`, rootless Podman, cosign, GitHub API/OCI configuration, writable quarantine/runtime directories and the required systemd units.
5. Run `deploy/scripts/backup.sh`.
6. Run migrations.
7. Synchronize admin password from `PASS`.
8. Build a versioned release directory, install its production dependencies, atomically repoint `/opt/kcml/current`, and restart `kcml.service`, `kcml-onboarding-worker.service` and `kcml-egress-proxy.service`.
9. Validate and reload the nginx config for `admin.hcasc.cz`, `auth.hcasc.cz`, `register.hcasc.cz`, the restricted KCML hostname regex and the default deny host.
10. Check `/health`, worker logs and egress-proxy socket readiness.
11. Keep the previous release for rollback; a failed health/service/socket check automatically repoints `current` to it.

## Automatic onboarding production gate

Do not enable `ONBOARDING_WORKER_ENABLED=true` until all of these are true:

- GitHub API authorization can create repository contents and pull requests and read checks and Actions runs; a least-privilege GitHub App is preferred, while an existing repository-capable token is supported; required checks match `.github/workflows/onboarding-pr.yml`;
- the trusted main workflow can push signed immutable images, SBOM and provenance to GHCR;
- the `kcml` system user can run rootless Podman and cannot access production application secrets from handler containers;
- `register.hcasc.cz` and a representative `kcmlNNNN.hcasc.cz` pass real DNS, TLS SAN, SNI and Host-routing tests;
- a staging reference handler completes token issuance, upload, PR/CI, signed deploy, public OAuth/MCP trial and `ACTIVE/HEALTHY`.

## Rollback

Run `deploy/scripts/rollback.sh <release-id>`. Database rollback is permitted
only to a migration-compatible application version. KCML identifiers, token
revocation epochs, audit events, and statistics are never reset.

Rollback must stop onboarding leases before changing the web release. An active
job remains disabled unless its exact source commit, build ID, image digest,
signature and attestations still verify after recovery.
