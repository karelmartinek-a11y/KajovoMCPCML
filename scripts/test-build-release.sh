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

mcp_manifest_path="$(jq -r '.manifestExamplePath' "$tmpdir/release/docs/onboarding-catalogs/mcp-1.6.json")"
external_manifest_path="$(jq -r '.manifestExamplePath' "$tmpdir/release/docs/onboarding-catalogs/external-api-1.0.json")"

test -f "$tmpdir/release/$mcp_manifest_path"
test -f "$tmpdir/release/$external_manifest_path"
