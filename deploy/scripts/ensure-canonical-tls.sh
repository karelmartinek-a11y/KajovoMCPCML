#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

base_domain="${1:?base domain required}"
component_suffix="${2:?component hostname suffix required}"
certificate_path="${3:?certificate path required}"
private_key_path="${4:?private key path required}"
status_root="/var/www/letsencrypt/.well-known/acme-challenge"
status_file="$status_root/kcml-dns-challenge.json"

for domain in "$base_domain" "$component_suffix"; do
  case "$domain" in
    ""|.*|*.|*..*|*[!a-z0-9.-]*) echo "invalid TLS domain" >&2; exit 1 ;;
  esac
done
case "$component_suffix" in
  "$base_domain"|*."$base_domain") ;;
  *) echo "component suffix is outside the base domain" >&2; exit 1 ;;
esac

certificate_covers_runtime() {
  test -f "$certificate_path" \
    && test -f "$private_key_path" \
    && openssl x509 -in "$certificate_path" -checkend 2592000 -noout >/dev/null 2>&1 \
    && openssl x509 -in "$certificate_path" -noout -text | grep -F "DNS:*.${base_domain}" >/dev/null \
    && openssl x509 -in "$certificate_path" -noout -text | grep -F "DNS:*.${component_suffix}" >/dev/null
}

if certificate_covers_runtime; then
  echo "canonical-tls:READY"
  exit 0
fi

command -v certbot >/dev/null
command -v dig >/dev/null
install -d -m 0755 "$status_root"
workdir="$(mktemp -d)"
auth_hook="$workdir/auth-hook.sh"
deploy_hook="$workdir/deploy-hook.sh"
cleanup() {
  rm -f "$status_file"
  rm -rf "$workdir"
}
trap cleanup EXIT

cat >"$auth_hook" <<'HOOK'
#!/usr/bin/env bash
set -Eeuo pipefail
record="_acme-challenge.${CERTBOT_DOMAIN}"
tmp="${KCML_ACME_STATUS_FILE}.tmp"
jq -nc --arg record "$record" --arg value "$CERTBOT_VALIDATION" \
  '{record:$record,value:$value,expiresInSeconds:900}' >"$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$KCML_ACME_STATUS_FILE"
echo "canonical-tls:WAITING_DNS record=$record value=$CERTBOT_VALIDATION"
for _attempt in $(seq 1 180); do
  if dig +short TXT "$record" | tr -d '"' | grep -Fx "$CERTBOT_VALIDATION" >/dev/null; then
    echo "canonical-tls:DNS_CONFIRMED record=$record"
    exit 0
  fi
  sleep 5
done
echo "canonical-tls:DNS_TIMEOUT record=$record" >&2
exit 1
HOOK

cat >"$deploy_hook" <<'HOOK'
#!/usr/bin/env bash
set -Eeuo pipefail
test -n "${RENEWED_LINEAGE:-}"
install -d -m 0700 "$(dirname "$KCML_TLS_CERT_PATH")" "$(dirname "$KCML_TLS_KEY_PATH")"
install -m 0644 "$RENEWED_LINEAGE/fullchain.pem" "$KCML_TLS_CERT_PATH"
install -m 0600 "$RENEWED_LINEAGE/privkey.pem" "$KCML_TLS_KEY_PATH"
HOOK
chmod 0700 "$auth_hook" "$deploy_hook"

KCML_ACME_STATUS_FILE="$status_file" \
KCML_TLS_CERT_PATH="$certificate_path" \
KCML_TLS_KEY_PATH="$private_key_path" \
certbot certonly \
  --non-interactive \
  --agree-tos \
  --register-unsafely-without-email \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook "$auth_hook" \
  --manual-cleanup-hook /bin/true \
  --deploy-hook "$deploy_hook" \
  --cert-name kcml-wildcards \
  --force-renewal \
  -d "$base_domain" \
  -d "*.${base_domain}" \
  -d "*.${component_suffix}"

certificate_covers_runtime
echo "canonical-tls:ISSUED"
