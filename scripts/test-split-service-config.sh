#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/legacy.env" <<'ENV'
DATABASE_URL=postgres://kcml:test@127.0.0.1/kcml
EGRESS_CAPABILITY_HMAC_KEY_BASE64=AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
PORT=
INTEGRATION_TOKEN_HMAC_KEY_ID=
ADMIN_BOOTSTRAP_USERNAME=
ENV

KCML_LEGACY_ENV="$tmp/legacy.env" \
KCML_CONFIG_ROOT="$tmp/config" \
  bash deploy/scripts/split-service-config.sh test-build >/dev/null

grep -qx 'NODE_ENV=production' "$tmp/config/web.env"
grep -qx 'BUILD_ID=test-build' "$tmp/config/web.env"
grep -qx 'ONBOARDING_WORKER_ENABLED=false' "$tmp/config/web.env"
grep -qx 'MONITOR_ENABLED=true' "$tmp/config/web.env"
! grep -q '^PORT=' "$tmp/config/web.env"
! grep -q '^INTEGRATION_TOKEN_HMAC_KEY_ID=' "$tmp/config/web.env"
! grep -q '^ADMIN_BOOTSTRAP_USERNAME=' "$tmp/config/web.env"
test "$(cat "$tmp/config/credentials/web/database_url")" = 'postgres://kcml:test@127.0.0.1/kcml'
test "$(cat "$tmp/config/credentials/web/egress_capability_hmac")" = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM='
test "$(cat "$tmp/config/credentials/monitor/egress_capability_hmac")" = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM='
