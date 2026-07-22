#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=/etc/kcml/kcml.env
release="${1:?release id required}"
target="/opt/kcml/releases/$release"
test -d "$target"
set -a
# shellcheck disable=SC1091
. /etc/kcml/kcml.env
set +a
: "${ADMIN_HOST:?ADMIN_HOST is required}"
bash "$(dirname "$0")/release-config.sh" restore "$release" "$target"
for unit in kcml kcml-onboarding-worker kcml-component-control-worker kcml-component-e2e-worker kcml-monitor kcml-egress-proxy kcml-alert-primary kcml-alert-backup; do
  if systemctl cat "$unit.service" >/dev/null 2>&1; then systemctl is-active --quiet "$unit.service"; fi
done
curl -fsS "https://${ADMIN_HOST}/health" >/dev/null
echo "rollback-ok:$release"
