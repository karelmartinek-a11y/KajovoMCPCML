#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

node deploy/scripts/render-nginx-config.mjs \
  deploy/nginx/kcml.conf "$tmp" \
  example.invalid admin.example.invalid auth.example.invalid register.example.invalid \
  /etc/kcml/tls/fullchain.pem /etc/kcml/tls/privkey.pem

grep -Fq 'server_name admin.example.invalid;' "$tmp"
grep -Fq 'server_name secrets.example.invalid;' "$tmp"
grep -Fq 'location = /.well-known/kcml-secret-api {' "$tmp"
grep -Fq 'location = /v1/secrets/resolve {' "$tmp"
grep -Fq 'server_name "~^kcml[0-9]{4,}\.example\.invalid$";' "$tmp"
grep -Fq 'server_name admin.example.invalid auth.example.invalid register.example.invalid secrets.example.invalid reference-api.example.invalid alerts-primary.example.invalid alerts-backup.example.invalid "~^kcml[0-9]{4,}\.example\.invalid$";' "$tmp"
test "$(grep -Fc 'return 444;' "$tmp")" -eq 2
# The nginx variables must remain literal in the rendered configuration.
# shellcheck disable=SC2016
http_redirect='return 308 https://$host$request_uri;'
test "$(grep -Fc "$http_redirect" "$tmp")" -eq 1
grep -Fq 'ssl_certificate /etc/kcml/tls/fullchain.pem;' "$tmp"
if grep -Eq '@[A-Z_]+@|hcasc\.cz' "$tmp"; then
  exit 1
fi

if node deploy/scripts/render-nginx-config.mjs \
  deploy/nginx/kcml.conf "$tmp" \
  example.invalid admin.other.invalid auth.example.invalid register.example.invalid \
  /etc/kcml/tls/fullchain.pem /etc/kcml/tls/privkey.pem 2>/dev/null; then
  exit 1
fi

for colliding_host in admin auth register; do
  admin_host=admin.example.invalid
  auth_host=auth.example.invalid
  register_host=register.example.invalid
  case "$colliding_host" in
    admin) admin_host=secrets.example.invalid ;;
    auth) auth_host=secrets.example.invalid ;;
    register) register_host=secrets.example.invalid ;;
  esac
  if node deploy/scripts/render-nginx-config.mjs \
    deploy/nginx/kcml.conf "$tmp" \
    example.invalid "$admin_host" "$auth_host" "$register_host" \
    /etc/kcml/tls/fullchain.pem /etc/kcml/tls/privkey.pem 2>/dev/null; then
    exit 1
  fi
done

derived_hosts="$(env -i PUBLIC_BASE_DOMAIN=example.invalid bash -c \
  '. deploy/scripts/control-plane-hosts.sh; printf "%s|%s|%s" "$ADMIN_HOST" "$AUTH_HOST" "$REGISTER_HOST"')"
test "$derived_hosts" = 'admin.example.invalid|auth.example.invalid|register.example.invalid'

custom_hosts="$(env -i PUBLIC_BASE_DOMAIN=example.invalid ADMIN_HOST=console.example.invalid \
  AUTH_HOST=identity.example.invalid REGISTER_HOST=intake.example.invalid bash -c \
  '. deploy/scripts/control-plane-hosts.sh; printf "%s|%s|%s" "$ADMIN_HOST" "$AUTH_HOST" "$REGISTER_HOST"')"
test "$custom_hosts" = 'console.example.invalid|identity.example.invalid|intake.example.invalid'
