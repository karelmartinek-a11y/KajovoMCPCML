#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/legacy.env" <<'ENV'
DATABASE_URL=postgres://kcml:test@127.0.0.1/kcml
DATABASE_MIGRATOR_URL=postgres://kcml:deploy@127.0.0.1/kcml
PUBLIC_BASE_DOMAIN=hcasc.cz
ADMIN_HOST=admin.hcasc.cz
AUTH_HOST=auth.hcasc.cz
REGISTER_HOST=register.hcasc.cz
QUARANTINE_ROOT=/var/lib/kcml/onboarding
ONBOARDING_WORKER_INTERVAL_MS=15000
MONITOR_INTERVAL_MS=60000
ALERT_PRIMARY_WEBHOOK_URL=https://alerts-primary.hcasc.cz/kcml-alert
ALERT_BACKUP_WEBHOOK_URL=https://alerts-backup.hcasc.cz/kcml-alert
GITHUB_OWNER=karelmartinek-a11y
GITHUB_REPO=KajovoMCPCML
GITHUB_TOKEN=gho_example_token_value_1234567890
OCI_REGISTRY=ghcr.io
OCI_IMAGE_NAMESPACE=karelmartinek-a11y/kajovomcpcml-handlers
OCI_CERTIFICATE_IDENTITY=https://github.com/karelmartinek-a11y/KajovoMCPCML/.github/workflows/onboarding-build.yml@refs/heads/main
OCI_CERTIFICATE_OIDC_ISSUER=https://token.actions.githubusercontent.com
PODMAN_BINARY=podman
COSIGN_BINARY=cosign
RUNTIME_SOCKET_ROOT=/var/lib/kcml/runtime
EGRESS_PROXY_SOCKET_PATH=/var/lib/kcml/egress/proxy.sock
EGRESS_CAPABILITY_HMAC_KEY_BASE64=AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
ACCESS_TOKEN_HMAC_KEY_BASE64=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB
INTEGRATION_TOKEN_HMAC_KEY_BASE64=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg==
SESSION_SECRET_BASE64=BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=
CSRF_SECRET_BASE64=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=
MFA_ENCRYPTION_KEY_BASE64=CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo=
ALERT_PRIMARY_HMAC_KEY_BASE64=DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0=
ALERT_BACKUP_HMAC_KEY_BASE64=Dg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4=
CONFIG_VAULT_MASTER_KEY_BASE64=CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=
PORT=
INTEGRATION_TOKEN_HMAC_KEY_ID=
ADMIN_BOOTSTRAP_USERNAME=
ENV

KCML_LEGACY_ENV="$tmp/legacy.env" \
KCML_CONFIG_ROOT="$tmp/config" \
  bash deploy/scripts/split-service-config.sh test-build >/dev/null

grep -qx 'NODE_ENV=production' "$tmp/config/web.env"
if grep -q '^PORT=' "$tmp/config/web.env"; then exit 1; fi
grep -qx 'BUILD_ID=test-build' "$tmp/config/web.env"
grep -qx 'BUILD_ID=test-build' "$tmp/config/worker.env"
grep -qx 'BUILD_ID=test-build' "$tmp/config/monitor.env"
grep -qx 'BUILD_ID=test-build' "$tmp/config/egress.env"
grep -qx 'GITHUB_OWNER=karelmartinek-a11y' "$tmp/config/worker.env"
grep -qx 'GITHUB_REPO=KajovoMCPCML' "$tmp/config/worker.env"
grep -qx 'ALERT_PRIMARY_WEBHOOK_URL=https://alerts-primary.hcasc.cz/kcml-alert' "$tmp/config/monitor.env"
grep -qx 'ALERT_BACKUP_WEBHOOK_URL=https://alerts-backup.hcasc.cz/kcml-alert' "$tmp/config/monitor.env"
if grep -q '^ONBOARDING_WORKER_ENABLED=' "$tmp/config/web.env"; then exit 1; fi
if grep -q '^MONITOR_ENABLED=' "$tmp/config/web.env"; then exit 1; fi
grep -qx 'ONBOARDING_WORKER_ENABLED=true' "$tmp/config/worker.env"
grep -qx 'MONITOR_ENABLED=true' "$tmp/config/monitor.env"
if grep -q '^INTEGRATION_TOKEN_HMAC_KEY_ID=' "$tmp/config/web.env"; then exit 1; fi
if grep -q '^ADMIN_BOOTSTRAP_USERNAME=' "$tmp/config/web.env"; then exit 1; fi
test "$(cat "$tmp/config/credentials/web/database_url")" = 'postgres://kcml:test@127.0.0.1/kcml'
test "$(cat "$tmp/config/credentials/web/access_token_hmac")" = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB'
test "$(cat "$tmp/config/credentials/web/integration_token_hmac")" = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=='
test "$(cat "$tmp/config/credentials/web/egress_capability_hmac")" = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM='
test "$(cat "$tmp/config/credentials/web/session_secret")" = 'BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ='
test "$(cat "$tmp/config/credentials/web/csrf_secret")" = 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc='
test "$(cat "$tmp/config/credentials/web/mfa_encryption")" = 'CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo='
test "$(cat "$tmp/config/credentials/worker/egress_capability_hmac")" = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM='
test "$(cat "$tmp/config/credentials/worker/github_token")" = 'gho_example_token_value_1234567890'
test "$(cat "$tmp/config/credentials/monitor/egress_capability_hmac")" = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM='
test "$(cat "$tmp/config/credentials/monitor/alert_primary_hmac")" = 'DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0='
test "$(cat "$tmp/config/credentials/monitor/alert_backup_hmac")" = 'Dg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4ODg4='
test "$(cat "$tmp/config/credentials/egress/egress_capability_hmac")" = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM='
test "$(cat "$tmp/config/credentials/admin-sync/database_url")" = 'postgres://kcml:deploy@127.0.0.1/kcml'
test "$(cat "$tmp/config/credentials/config_vault_master_key")" = 'CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk='

grep -q '/etc/kcml/credentials/worker/database_url' deploy/scripts/kcml-handler-preload-wrapper.sh
if grep -q '/etc/kcml/kcml.env' deploy/scripts/kcml-handler-preload-wrapper.sh; then exit 1; fi
grep -q 'worker database credential is unavailable' deploy/scripts/kcml-handler-preload-wrapper.sh
