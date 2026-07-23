#!/usr/bin/env bash
set -euo pipefail
umask 077

legacy_env="${KCML_LEGACY_ENV:-/etc/kcml/kcml.env}"
test -r "$legacy_env"
set -a
# shellcheck disable=SC1090,SC1091
. "$legacy_env"
set +a

if [ -n "${1:-}" ]; then
  BUILD_ID="$1"
fi
: "${BUILD_ID:?BUILD_ID is required}"
: "${DATABASE_URL:?DATABASE_URL is required}"

root="${KCML_CONFIG_ROOT:-/etc/kcml}"
credentials="$root/credentials"
install -d -m 0700 "$root" "$credentials"
for service in web worker monitor egress secret-broker migrator admin-sync alert-primary-sink alert-backup-sink; do
  install -d -m 0700 "$credentials/$service"
done

vault_key_file="$credentials/config_vault_master_key"
if [ -n "${CONFIG_VAULT_MASTER_KEY_BASE64:-}" ]; then
  vault_key="$CONFIG_VAULT_MASTER_KEY_BASE64"
elif [ -s "$vault_key_file" ]; then
  vault_key="$(cat "$vault_key_file")"
else
  vault_key="$(openssl rand -base64 32 | tr -d '\n')"
fi
node - "$vault_key" <<'NODE'
const value = process.argv[2];
const decoded = Buffer.from(value, "base64");
if (decoded.length !== 32 || decoded.toString("base64") !== value) process.exit(1);
NODE
printf '%s' "$vault_key" > "$vault_key_file"
chmod 0600 "$vault_key_file"

write_credential() {
  local service="$1" name="$2" value="$3"
  printf '%s' "$value" > "$credentials/$service/$name"
  chmod 0600 "$credentials/$service/$name"
}

write_optional_credential() {
  local service="$1" name="$2" value="$3"
  if [ -n "$value" ]; then
    write_credential "$service" "$name" "$value"
  fi
}

write_env() {
  local target="$1"
  shift
  : > "$target"
  for key in "$@"; do
    if [ -n "${!key:-}" ]; then
      printf '%s=%s\n' "$key" "${!key}" >> "$target"
    fi
  done
  chmod 0600 "$target"
}

export NODE_ENV="production"
export BUILD_ID
export ONBOARDING_WORKER_ENABLED="false"
export MONITOR_ENABLED="true"
write_env "$root/web.env" \
  NODE_ENV PORT BUILD_ID CONFIG_VAULT_MASTER_KEY_ID PUBLIC_BASE_DOMAIN ADMIN_HOST AUTH_HOST REGISTER_HOST QUARANTINE_ROOT EGRESS_PROXY_SOCKET_PATH WILDCARD_TLS_CERT_PATH TRUSTED_PROXY_CIDRS LOG_LEVEL UI_TIME_ZONE

export ONBOARDING_WORKER_ENABLED="true"
export MONITOR_ENABLED="false"
write_env "$root/worker.env" \
  NODE_ENV BUILD_ID ONBOARDING_WORKER_ENABLED ONBOARDING_WORKER_INTERVAL_MS PUBLIC_BASE_DOMAIN ADMIN_HOST AUTH_HOST REGISTER_HOST QUARANTINE_ROOT GITHUB_OWNER GITHUB_REPO GITHUB_APP_ID GITHUB_APP_INSTALLATION_ID OCI_REGISTRY OCI_IMAGE_NAMESPACE OCI_CERTIFICATE_IDENTITY OCI_CERTIFICATE_OIDC_ISSUER PODMAN_BINARY COSIGN_BINARY RUNTIME_SOCKET_ROOT EGRESS_PROXY_SOCKET_PATH LOG_LEVEL UI_TIME_ZONE CONFIG_VAULT_MASTER_KEY_ID

export ONBOARDING_WORKER_ENABLED="false"
export MONITOR_ENABLED="true"
write_env "$root/monitor.env" \
  NODE_ENV BUILD_ID MONITOR_ENABLED MONITOR_INTERVAL_MS PUBLIC_BASE_DOMAIN ADMIN_HOST AUTH_HOST REGISTER_HOST ALERT_PRIMARY_WEBHOOK_URL ALERT_BACKUP_WEBHOOK_URL OCI_REGISTRY OCI_IMAGE_NAMESPACE OCI_CERTIFICATE_IDENTITY OCI_CERTIFICATE_OIDC_ISSUER PODMAN_BINARY COSIGN_BINARY RUNTIME_SOCKET_ROOT EGRESS_PROXY_SOCKET_PATH AUDIT_ARCHIVE_PATH LOG_LEVEL UI_TIME_ZONE CONFIG_VAULT_MASTER_KEY_ID

export MONITOR_ENABLED="false"
write_env "$root/egress.env" \
  NODE_ENV BUILD_ID PUBLIC_BASE_DOMAIN EGRESS_PROXY_SOCKET_PATH RUNTIME_SOCKET_ROOT LOG_LEVEL UI_TIME_ZONE CONFIG_VAULT_MASTER_KEY_ID

write_env "$root/secret-broker.env" \
  NODE_ENV BUILD_ID PUBLIC_BASE_DOMAIN SECRET_BROKER_SOCKET_PATH LOG_LEVEL UI_TIME_ZONE CONFIG_VAULT_MASTER_KEY_ID

export PORT="3011"
export ALERT_SINK_CHANNEL="PRIMARY"
export ALERT_SINK_STATE_DIR="/var/lib/kcml/alert-primary-sink"
write_env "$root/alert-primary-sink.env" PORT ALERT_SINK_CHANNEL ALERT_SINK_STATE_DIR
export PORT="3012"
export ALERT_SINK_CHANNEL="BACKUP"
export ALERT_SINK_STATE_DIR="/var/lib/kcml/alert-backup-sink"
write_env "$root/alert-backup-sink.env" PORT ALERT_SINK_CHANNEL ALERT_SINK_STATE_DIR

database_app_url="${DATABASE_APP_URL:-$DATABASE_URL}"
database_admin_sync_url="${DATABASE_ADMIN_SYNC_URL:-${DATABASE_MIGRATOR_URL:-$DATABASE_URL}}"
write_credential web database_url "$database_app_url"
write_credential web access_token_hmac "${ACCESS_TOKEN_HMAC_KEY_BASE64:-}"
write_credential web integration_token_hmac "${INTEGRATION_TOKEN_HMAC_KEY_BASE64:-}"
write_credential web egress_capability_hmac "${EGRESS_CAPABILITY_HMAC_KEY_BASE64:-}"
write_credential web session_secret "${SESSION_SECRET_BASE64:-}"
write_credential web csrf_secret "${CSRF_SECRET_BASE64:-}"
write_credential web mfa_encryption "${MFA_ENCRYPTION_KEY_BASE64:-}"

write_credential worker database_url "$database_app_url"
write_credential worker egress_capability_hmac "${EGRESS_CAPABILITY_HMAC_KEY_BASE64:-}"
write_optional_credential worker github_token "${GITHUB_TOKEN:-}"
write_optional_credential worker github_app_private_key "${GITHUB_APP_PRIVATE_KEY_BASE64:-}"

write_credential monitor database_url "$database_app_url"
write_credential monitor egress_capability_hmac "${EGRESS_CAPABILITY_HMAC_KEY_BASE64:-}"
write_credential monitor alert_primary_hmac "${ALERT_PRIMARY_HMAC_KEY_BASE64:-}"
write_credential monitor alert_backup_hmac "${ALERT_BACKUP_HMAC_KEY_BASE64:-}"

write_credential egress database_url "$database_app_url"
write_credential egress egress_capability_hmac "${EGRESS_CAPABILITY_HMAC_KEY_BASE64:-}"

write_credential secret-broker database_url "$database_app_url"

write_credential migrator database_url "${DATABASE_MIGRATOR_URL:-$DATABASE_URL}"
write_credential admin-sync database_url "$database_admin_sync_url"
write_credential alert-primary-sink alert_hmac "${ALERT_PRIMARY_HMAC_KEY_BASE64:-}"
write_credential alert-backup-sink alert_hmac "${ALERT_BACKUP_HMAC_KEY_BASE64:-}"

find "$credentials" -type d -exec chmod 0700 {} +
find "$credentials" -type f -exec chmod 0600 {} +
echo "service-config-split:$BUILD_ID"
