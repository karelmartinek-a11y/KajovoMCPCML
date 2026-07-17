#!/usr/bin/env bash
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/legacy.env" <<'ENV'
DATABASE_URL=postgres://kcml:test@127.0.0.1/kcml
DATABASE_MIGRATOR_URL=postgres://kcml:deploy@127.0.0.1/kcml
EGRESS_CAPABILITY_HMAC_KEY_BASE64=AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
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
if grep -q '^BUILD_ID=' "$tmp/config/web.env"; then exit 1; fi
if grep -q '^ONBOARDING_WORKER_ENABLED=' "$tmp/config/web.env"; then exit 1; fi
if grep -q '^MONITOR_ENABLED=' "$tmp/config/web.env"; then exit 1; fi
if grep -q '^INTEGRATION_TOKEN_HMAC_KEY_ID=' "$tmp/config/web.env"; then exit 1; fi
if grep -q '^ADMIN_BOOTSTRAP_USERNAME=' "$tmp/config/web.env"; then exit 1; fi
test "$(cat "$tmp/config/credentials/web/database_url")" = 'postgres://kcml:test@127.0.0.1/kcml'
test "$(cat "$tmp/config/credentials/admin-sync/database_url")" = 'postgres://kcml:deploy@127.0.0.1/kcml'
test "$(cat "$tmp/config/credentials/config_vault_master_key")" = 'CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk='
test ! -e "$tmp/config/credentials/web/egress_capability_hmac"
test ! -e "$tmp/config/credentials/monitor/egress_capability_hmac"

grep -q '/etc/kcml/credentials/worker/database_url' deploy/scripts/kcml-handler-preload-wrapper.sh
if grep -q '/etc/kcml/kcml.env' deploy/scripts/kcml-handler-preload-wrapper.sh; then exit 1; fi
grep -q 'worker database credential is unavailable' deploy/scripts/kcml-handler-preload-wrapper.sh
