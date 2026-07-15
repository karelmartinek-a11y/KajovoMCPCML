#!/usr/bin/env bash
set -euo pipefail

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

BUILD_ID="test-build-release" bash scripts/build-release.sh "$tmpdir/release"

test -f "$tmpdir/release/docs/onboarding-manifest-v1.5.example.json"
test -f "$tmpdir/release/docs/service-manifest-external-api-v1.0.example.json"
test -f "$tmpdir/release/docs/onboarding-catalogs/mcp-1.6.json"
test -f "$tmpdir/release/docs/onboarding-catalogs/external-api-1.0.json"
test -f "$tmpdir/release/apps/server/dist/cli/release-kcml0002-smoke.js"
test -f "$tmpdir/release/apps/server/dist/cli/release-kcml0002-runtime-refresh.js"
test -f "$tmpdir/release/deploy/scripts/kcml-handler-preload-wrapper.sh"

mcp_manifest_path="$(jq -r '.manifestExamplePath' "$tmpdir/release/docs/onboarding-catalogs/mcp-1.6.json")"
external_manifest_path="$(jq -r '.manifestExamplePath' "$tmpdir/release/docs/onboarding-catalogs/external-api-1.0.json")"

test -f "$tmpdir/release/$mcp_manifest_path"
test -f "$tmpdir/release/$external_manifest_path"
grep -q 'release-kcml0002-smoke.js' "$tmpdir/release/deploy/scripts/install-release.sh"
grep -q 'release-kcml0002-runtime-refresh.js' "$tmpdir/release/deploy/scripts/install-release.sh"
grep -q 'kcml-handler-preload-wrapper' "$tmpdir/release/deploy/scripts/install-release.sh"
! grep -q '/api/mcp-servers/$kcml0002_server_id/test' "$tmpdir/release/deploy/scripts/install-release.sh"
