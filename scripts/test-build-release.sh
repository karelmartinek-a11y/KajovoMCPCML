#!/usr/bin/env bash
set -euo pipefail

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/kcml-build-release.XXXXXX")"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

test -x node_modules/.bin/vitest
BUILD_ID="test-build-release" bash scripts/build-release.sh "$tmpdir/release"
test -x node_modules/.bin/vitest

test -f "$tmpdir/release/docs/onboarding-manifest-2026.07.21.example.json"
test -f "$tmpdir/release/docs/component-manifest-2026.07.21.schema.json"
test -f "$tmpdir/release/docs/service-manifest-external-api-v1.0.example.json"
test -f "$tmpdir/release/docs/onboarding-catalogs/component-2026.07.21.json"
test -f "$tmpdir/release/KajovoCML_Onboarding_Catalog_2026.07.21.docx"
test -f "$tmpdir/release/KajovoCML_Onboarding_Catalog_2026.07.21.pdf"
test -f "$tmpdir/release/docs/releases/2026.07.21/KajovoCML_Onboarding_Catalog_2026.07.21.pdf"
test -f "$tmpdir/release/docs/onboarding-catalogs/external-api-1.0.json"
test -f "$tmpdir/release/apps/server/dist/cli/release-kcml0002-smoke.js"
test -f "$tmpdir/release/apps/server/dist/cli/release-kcml0002-runtime-refresh.js"
test -f "$tmpdir/release/apps/server/dist/cli/migrate-mfa-secrets.js"
test -f "$tmpdir/release/apps/server/dist/cli/import-operational-config.js"
test -f "$tmpdir/release/deploy/scripts/kcml-handler-preload-wrapper.sh"
test -f "$tmpdir/release/deploy/scripts/render-nginx-config.mjs"

mcp_manifest_path="$(jq -r '.manifestExamplePath' "$tmpdir/release/docs/onboarding-catalogs/component-2026.07.21.json")"
external_manifest_path="$(jq -r '.manifestExamplePath' "$tmpdir/release/docs/onboarding-catalogs/external-api-1.0.json")"

test -f "$tmpdir/release/$mcp_manifest_path"
test -f "$tmpdir/release/$external_manifest_path"
grep -q 'release-kcml0002-smoke.js' "$tmpdir/release/deploy/scripts/install-release.sh"
grep -q 'release-kcml0002-runtime-refresh.js' "$tmpdir/release/deploy/scripts/install-release.sh"
grep -q 'migrate-mfa-secrets.js' "$tmpdir/release/deploy/scripts/install-release.sh"
grep -q 'import-operational-config.js" --refresh-build-id' "$tmpdir/release/deploy/scripts/install-release.sh"
grep -q 'CONFIG_VAULT_MASTER_KEY_BASE64_FILE=/etc/kcml/credentials/config_vault_master_key' "$tmpdir/release/deploy/scripts/install-release.sh"
test "$(grep -c '^step sync-admin-password$' "$tmpdir/release/deploy/scripts/install-release.sh")" = "1"
grep -Fq "node \"\$source_dir/apps/server/dist/cli/sync-admin-password.js\"" "$tmpdir/release/deploy/scripts/install-release.sh"
if grep -q 'admin_sync_totp_file' "$tmpdir/release/deploy/scripts/install-release.sh"; then
  exit 1
fi
grep -Fq "podman_runtime_dir=\"/run/user/\${kcml_uid}\"" "$tmpdir/release/deploy/scripts/install-release.sh"
grep -Fq "DBUS_SESSION_BUS_ADDRESS=\"unix:path=\${podman_runtime_dir}/bus\"" "$tmpdir/release/deploy/scripts/install-release.sh"
grep -q 'kcml-handler-preload-wrapper' "$tmpdir/release/deploy/scripts/install-release.sh"
if grep -Fq "/api/mcp-servers/\$kcml0002_server_id/test" "$tmpdir/release/deploy/scripts/install-release.sh"; then
  exit 1
fi
if grep -R -E 'hcasc\.cz|karmar78' "$tmpdir/release/deploy/nginx" "$tmpdir/release/deploy/systemd" "$tmpdir/release/deploy/scripts" >/dev/null; then
  exit 1
fi
