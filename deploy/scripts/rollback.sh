#!/usr/bin/env bash
set -euo pipefail

release="${1:?release id required}"
target="/opt/kcml/releases/$release"
test -d "$target"
ln -sfn "$target" /opt/kcml/current
systemctl restart kcml kcml-egress-proxy kcml-onboarding-worker
systemctl reload nginx
systemctl is-active --quiet kcml-egress-proxy
systemctl is-active --quiet kcml-onboarding-worker
test -S "${EGRESS_PROXY_SOCKET_PATH:-/var/lib/kcml/egress/proxy.sock}"
curl -fsS https://admin.hcasc.cz/health >/dev/null
echo "rollback-ok:$release"
