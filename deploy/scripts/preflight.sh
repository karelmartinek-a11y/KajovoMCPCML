#!/usr/bin/env bash
set -euo pipefail

nginx -t
ss -ltnp | grep -E ':(80|443)\s' >/dev/null
test -n "${DATABASE_URL:-}"
test -n "${PUBLIC_BASE_DOMAIN:-}"
test -n "${ADMIN_HOST:-}"
test -n "${AUTH_HOST:-}"
test -n "${REGISTER_HOST:-}"
test -n "${KCML_COMPONENT_HOST_SUFFIX:-}"
test -n "${ACCESS_TOKEN_HMAC_KEY_BASE64:-}"
test -n "${INTEGRATION_TOKEN_HMAC_KEY_BASE64:-}"
test -n "${EGRESS_CAPABILITY_HMAC_KEY_BASE64:-}"
test -n "${SESSION_SECRET_BASE64:-}"
test -n "${CSRF_SECRET_BASE64:-}"
test -n "${MFA_ENCRYPTION_KEY_BASE64:-}"
test "${ONBOARDING_WORKER_ENABLED:-}" = "true"
test -n "${GITHUB_OWNER:-}"
test -n "${GITHUB_REPO:-}"
if [ -z "${GITHUB_TOKEN:-}" ]; then
  test -n "${GITHUB_APP_ID:-}"
  test -n "${GITHUB_APP_INSTALLATION_ID:-}"
  test -n "${GITHUB_APP_PRIVATE_KEY_BASE64:-}"
fi
test -n "${OCI_IMAGE_NAMESPACE:-}"
test -n "${OCI_CERTIFICATE_IDENTITY:-}"
case "${OCI_CERTIFICATE_IDENTITY}" in
  https://github.com/*/.github/workflows/onboarding-build.yml@refs/heads/main) ;;
  *) echo "invalid OCI_CERTIFICATE_IDENTITY" >&2; exit 1 ;;
esac
test "${OCI_CERTIFICATE_OIDC_ISSUER:-https://token.actions.githubusercontent.com}" = "https://token.actions.githubusercontent.com"
test "${MONITOR_ENABLED:-}" = "true"
test -n "${ALERT_PRIMARY_WEBHOOK_URL:-}"
test -n "${ALERT_PRIMARY_HMAC_KEY_BASE64:-}"
test -n "${ALERT_BACKUP_WEBHOOK_URL:-}"
test -n "${ALERT_BACKUP_HMAC_KEY_BASE64:-}"
test "${ALERT_PRIMARY_WEBHOOK_URL}" != "${ALERT_BACKUP_WEBHOOK_URL}"
tls_cert_path="${WILDCARD_TLS_CERT_PATH:-/etc/kcml/tls/fullchain.pem}"
tls_key_path="${WILDCARD_TLS_KEY_PATH:-${tls_cert_path%/*}/privkey.pem}"
test -f "$tls_cert_path"
test -f "$tls_key_path"
openssl x509 -in "$tls_cert_path" -checkend 86400 -noout
openssl x509 -in "$tls_cert_path" -noout -text | grep -F "DNS:*.${PUBLIC_BASE_DOMAIN}" >/dev/null
openssl x509 -in "$tls_cert_path" -noout -text | grep -F "DNS:*.${KCML_COMPONENT_HOST_SUFFIX}" >/dev/null
command -v "${PODMAN_BINARY:-podman}" >/dev/null
command -v systemd-run >/dev/null
command -v "${COSIGN_BINARY:-cosign}" >/dev/null
command -v age >/dev/null
test -r "${AGE_RECIPIENT_FILE:-/etc/kcml/backup.age.recipient}"
grep -Eq '^kcml:' /etc/subuid
grep -Eq '^kcml:' /etc/subgid
install -d -m 0700 -o kcml -g kcml /run/kcml-podman
install -d -m 0700 -o kcml -g kcml /var/lib/kcml/podman /var/lib/kcml/podman/data /var/lib/kcml/podman/config
kcml_uid="$(id -u kcml)"
loginctl enable-linger kcml
systemctl start "user@${kcml_uid}.service"
test -S "/run/user/${kcml_uid}/bus"
podman_binary="$(command -v "${PODMAN_BINARY:-podman}")"
runuser -u kcml -- env \
  XDG_RUNTIME_DIR="/run/user/${kcml_uid}" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${kcml_uid}/bus" \
  systemd-run --user --quiet --wait --pipe --collect --unit=kcml-podman-preflight \
    --property WorkingDirectory=/var/lib/kcml/podman \
    --property UMask=0077 \
    --setenv HOME=/var/lib/kcml/podman \
    --setenv USER=kcml \
    --setenv LOGNAME=kcml \
    --setenv XDG_DATA_HOME=/var/lib/kcml/podman/data \
    --setenv XDG_CONFIG_HOME=/var/lib/kcml/podman/config \
    --setenv "XDG_RUNTIME_DIR=/run/user/${kcml_uid}" \
    --setenv "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${kcml_uid}/bus" \
    "${podman_binary}" info --format '{{.Host.Security.Rootless}}' | grep -Fx true >/dev/null
audit_archive_dir="$(dirname "${AUDIT_ARCHIVE_PATH:-/var/lib/kcml/audit/archive.jsonl}")"
install -d -m 0700 -o kcml -g kcml "${QUARANTINE_ROOT:-/var/lib/kcml/onboarding}" "${RUNTIME_SOCKET_ROOT:-/var/lib/kcml/runtime}" "$audit_archive_dir"
install -d -m 0711 -o kcml -g kcml /var/lib/kcml/egress /var/lib/kcml/secret-broker
runuser -u kcml -- test -w "${QUARANTINE_ROOT:-/var/lib/kcml/onboarding}"
runuser -u kcml -- test -w "${RUNTIME_SOCKET_ROOT:-/var/lib/kcml/runtime}"
runuser -u kcml -- test -w /var/lib/kcml/egress
runuser -u kcml -- test -w /var/lib/kcml/secret-broker
runuser -u kcml -- test -w "$audit_archive_dir"
for service in web worker monitor egress migrator admin-sync alert-primary-sink alert-backup-sink; do
  test "$(stat -c '%a' "/etc/kcml/credentials/$service")" = "700"
  test -z "$(find "/etc/kcml/credentials/$service" -type f ! -perm 0600 -print -quit)"
done
node --check "${KCML_RELEASE_SOURCE:-/opt/kcml/current}/deploy/alert-sink/receiver.mjs" >/dev/null
echo "preflight-ok"
