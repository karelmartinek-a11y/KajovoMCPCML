#!/usr/bin/env bash
set -euo pipefail

nginx -t
ss -ltnp | grep -E ':(80|443)\s' >/dev/null
test -n "${DATABASE_URL:-}"
test -n "${ACCESS_TOKEN_HMAC_KEY_BASE64:-}"
test -n "${INTEGRATION_TOKEN_HMAC_KEY_BASE64:-}"
test -n "${EGRESS_CAPABILITY_HMAC_KEY_BASE64:-}"
test -n "${SESSION_SECRET_BASE64:-}"
test -n "${CSRF_SECRET_BASE64:-}"
test -n "${MFA_ENCRYPTION_KEY_BASE64:-}"
test "${ONBOARDING_WORKER_ENABLED:-}" = "true"
test -n "${GITHUB_OWNER:-}"
test -n "${GITHUB_REPO:-}"
test -n "${GITHUB_APP_ID:-}"
test -n "${GITHUB_APP_INSTALLATION_ID:-}"
test -n "${GITHUB_APP_PRIVATE_KEY_BASE64:-}"
test -n "${OCI_IMAGE_NAMESPACE:-}"
test -n "${OCI_SIGNING_PUBLIC_KEY:-}"
test -f "${OCI_SIGNING_PUBLIC_KEY}"
runuser -u kcml -- test -r "${OCI_SIGNING_PUBLIC_KEY}"
test -f "${WILDCARD_TLS_CERT_PATH:-/etc/letsencrypt/live/wildcard.hcasc.cz/fullchain.pem}"
openssl x509 -in "${WILDCARD_TLS_CERT_PATH:-/etc/letsencrypt/live/wildcard.hcasc.cz/fullchain.pem}" -checkend 86400 -noout
openssl x509 -in "${WILDCARD_TLS_CERT_PATH:-/etc/letsencrypt/live/wildcard.hcasc.cz/fullchain.pem}" -noout -text | grep -F 'DNS:*.hcasc.cz' >/dev/null
command -v "${PODMAN_BINARY:-podman}" >/dev/null
command -v "${COSIGN_BINARY:-cosign}" >/dev/null
grep -Eq '^kcml:' /etc/subuid
grep -Eq '^kcml:' /etc/subgid
install -d -m 0700 -o kcml -g kcml /run/kcml-podman
install -d -m 0700 -o kcml -g kcml /var/lib/kcml/podman /var/lib/kcml/podman/data /var/lib/kcml/podman/config
runuser -u kcml -- env HOME=/var/lib/kcml/podman XDG_DATA_HOME=/var/lib/kcml/podman/data XDG_CONFIG_HOME=/var/lib/kcml/podman/config XDG_RUNTIME_DIR=/run/kcml-podman "${PODMAN_BINARY:-podman}" info --format '{{.Host.Security.Rootless}}' | grep -Fx true >/dev/null
install -d -m 0700 -o kcml -g kcml "${QUARANTINE_ROOT:-/var/lib/kcml/onboarding}" "${RUNTIME_SOCKET_ROOT:-/var/lib/kcml/runtime}" /var/lib/kcml/egress
runuser -u kcml -- test -w "${QUARANTINE_ROOT:-/var/lib/kcml/onboarding}"
runuser -u kcml -- test -w "${RUNTIME_SOCKET_ROOT:-/var/lib/kcml/runtime}"
runuser -u kcml -- test -w /var/lib/kcml/egress
echo "preflight-ok"
